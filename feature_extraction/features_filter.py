from bs4 import BeautifulSoup

import requests

# ['arp', 'coap', 'data', 'data-text-lines', 'dhcp', 'dns', 'eth', 'ethertype', 'http', 'icmp', 'ip', 'llc', 'pkix1explicit', 'pkix1implicit', 'tcp', 'tls', 'udp', 'x509ce', 'x509sat']



protocol_urls = {
    "tcp":"https://www.wireshark.org/docs/dfref/t/tcp.html",
    "tls" : "https://www.wireshark.org/docs/dfref/t/tls.html", 
    "arp" : "https://www.wireshark.org/docs/dfref/a/arp.html", 
    "dhcp" : "https://www.wireshark.org/docs/dfref/d/dhcp.html",
    "coap" : "https://www.wireshark.org/docs/dfref/c/coap.html",
    "data" : "https://www.wireshark.org/docs/dfref/d/data.html",
    "dns" : "https://www.wireshark.org/docs/dfref/d/dns.html",
    "eth" : "https://www.wireshark.org/docs/dfref/e/eth.html",
    "http" : "https://www.wireshark.org/docs/dfref/h/http.html",
    "icmp" : "https://www.wireshark.org/docs/dfref/i/icmp.html",
    "icmpv6" : "https://www.wireshark.org/docs/dfref/i/icmpv6.html",
    "ip" : "https://www.wireshark.org/docs/dfref/i/ip.html",
    "llc" : "https://www.wireshark.org/docs/dfref/l/llc.html",
    "pkix1explicit" : "https://www.wireshark.org/docs/dfref/p/pkix1explicit.html",
    "pkix1implicit" : "https://www.wireshark.org/docs/dfref/p/pkix1implicit.html",
    "udp" : "https://www.wireshark.org/docs/dfref/u/udp.html",
    "x509ce" : "https://www.wireshark.org/docs/dfref/x/x509ce.html",
    "x509sat" : "https://www.wireshark.org/docs/dfref/x/x509sat.html",
    "eapol" : "https://www.wireshark.org/docs/dfref/e/eapol.html",
    "udp" : "https://www.wireshark.org/docs/dfref/u/udp.html",
    "bootp" : "https://www.wireshark.org/docs/dfref/b/bootp.html",
    "ntp" : "https://www.wireshark.org/docs/dfref/n/ntp.html",
}

def get_numeric_features(protocol_name):
    features = []
    url = protocol_urls[protocol_name]
    r = requests.get(url)

    soup = BeautifulSoup(r.text, 'html.parser')

    rows = soup.find("table", {"class":'display-filter'}).find_all('tr')

    for row in rows:
        cells = row.find_all('td')
        try:
            features.append(cells[0].get_text())
        except:
            pass
    
    return features

def get_ip_option_padding_feature_list():
    return [
        "ip.opt.padding"
    ]

def get_ip_option_router_alert_feature_list():
    return [
        "ip.opt.ra"
    ]

def get_tshark_valid_ntp_protocol_feature_list():
    features = get_numeric_features('ntp')
    unsed = [
        "ntppriv.seq",
        "ntppriv.reqcode",
        "ntppriv.impl",
        "ntppriv.flags.r",
        "ntppriv.flags.more",
        "ntppriv.auth_seq",
        "ntppriv.auth",
        "ntpctrl.trapmsg",
        "ntpctrl.sys_status.li",
        "ntpctrl.sys_status.count",
        "ntpctrl.sys_status.code",
        "ntpctrl.sys_status.clksrc",
        "ntpctrl.status",
        "ntpctrl.sequence",
        "ntpctrl.peer_status.selection",
        "ntpctrl.peer_status.reserved",
        "ntpctrl.peer_status.reach",
        "ntpctrl.peer_status.count",
        "ntpctrl.peer_status.config",
        "ntpctrl.peer_status.code",
        "ntpctrl.peer_status.authentic",
        "ntpctrl.peer_status.authenable",
        "ntpctrl.offset",
        "ntpctrl.item",
        "ntpctrl.flags2.r",
        "ntpctrl.flags2.opcode",
        "ntpctrl.flags2.more",
        "ntpctrl.flags2.error",
        "ntpctrl.flags2",
        "ntpctrl.err_status",
        "ntpctrl.data",
        "ntpctrl.count",
        "ntpctrl.clock_status.status",
        "ntpctrl.clock_status.code",
        "ntpctrl.associd",
        "ntp.priv.monlist.itemsize",
        "ntp.priv.monlist.item",
        "ntp.priv.mode7.bad_pakets",
        "ntp.ext.vallen",
        "ntp.ext.val",
        "ntp.ext.tstamp",
        "ntp.ext.siglen",
        "ntp.ext.sig",
        "ntp.ext.op",
        "ntp.ext.len",
        "ntp.ext.fstamp",
        "ntp.ext.flags.vn",
        "ntp.ext.flags.r",
        "ntp.ext.flags.error",
        "ntp.ext.flags",
        "ntp.ext.associd",
        "ntp.ctrl.peer_status.reserved",
    ]
    for u in unsed:
        if u in features:
            features.remove(u)
    
    return features


def get_tshark_valid_bootp_protocol_feature_list():
    features = get_numeric_features('bootp')
    unsed = [
        "bootp.option.vendor.cl.oui_bytes",
        "bootp.option.vendor.cl.mta_mac_address",
        "bootp.option.vendor.cl.model_number",
        "bootp.option.vendor.cl.hardware_version",
        "bootp.option.vendor.cl.firewall_policy_file_version",
        "bootp.option.vendor.cl.esafe_type",
        "bootp.option.vendor.cl.esafe_config_file_devices",
        "bootp.option.vendor.cl.end",
        "bootp.option.vendor.cl.device_type",
        "bootp.option.vendor.cl.device_id_x509",
        "bootp.option.vendor.cl.device_id_ca",
        "bootp.option.vendor.cl.correlation_ID",
        "bootp.option.vendor.cl.cm_ps_system_desc",
        "bootp.option.vendor.cl.cm_ps_firmware_revision",
        "bootp.option.vendor.cl.cablecard_capability",
        "bootp.option.vendor.cl.boot_rom_version",
        "bootp.option.vendor.cl.address_realm",
        "bootp.option.vendor.bsdp.version",
        "bootp.option.vendor.bsdp.suboption",
        "bootp.option.vendor.bsdp.server_priority",
        "bootp.option.vendor.bsdp.server_identifier",
        "bootp.option.vendor.bsdp.selected_boot_image_id",
        "bootp.option.vendor.bsdp.reply_port",
        "bootp.option.vendor.bsdp.netboot_firmware",
        "bootp.option.vendor.bsdp.message_type",
        "bootp.option.vendor.bsdp.message_size",
        "bootp.option.vendor.bsdp.default_boot_image_id",
        "bootp.option.vendor.bsdp.boot_image_list_path",
        "bootp.option.vendor.bsdp.boot_image_list",
        "bootp.option.vendor.bsdp.boot_image.name_len",
        "bootp.option.vendor.bsdp.boot_image.name",
        "bootp.option.vendor.bsdp.boot_image.index",
        "bootp.option.vendor.bsdp.boot_image.desc",
        "bootp.option.vendor.bsdp.boot_image.attribute.reserved",
        "bootp.option.vendor.bsdp.boot_image.attribute.kind",
        "bootp.option.vendor.bsdp.boot_image.attribute.install",
        "bootp.option.vendor.bsdp.boot_image.attribute",
        "bootp.option.vendor.bsdp.attributes_filter_list",
        "bootp.option.vendor.avaya.vlantest.invalid",
        "bootp.option.vendor.avaya.vlantest",
        "bootp.option.vendor.avaya.tlssrvr",
        "bootp.option.vendor.avaya.static",
        "bootp.option.vendor.avaya.snmpstring",
        "bootp.option.vendor.avaya.snmpadd",
        "bootp.option.vendor.avaya.procstat",
        "bootp.option.vendor.avaya.procpswd",
        "bootp.option.vendor.avaya.phy2stat",
        "bootp.option.vendor.avaya.phy1stat",
        "bootp.option.vendor.avaya.mcipadd",
        "bootp.option.vendor.avaya.loglocal",
        "bootp.option.vendor.avaya.l2qvlan.invalid",
        "bootp.option.vendor.avaya.l2qvlan",
        "bootp.option.vendor.avaya.l2q",
        "bootp.option.vendor.avaya.icmpred",
        "bootp.option.vendor.avaya.icmpdu",
        "bootp.option.vendor.avaya.httpsrvr",
        "bootp.option.vendor.avaya.httpdir",
        "bootp.option.vendor.avaya.dot1x",
        "bootp.option.vendor.avaya",
        "bootp.option.vendor.arubaiap.password",
        "bootp.option.vendor.arubaiap.name_org",
        "bootp.option.vendor.arubaiap.amp_ip",
        "bootp.option.vendor.arubaiap",
        "bootp.option.vendor.arubaap.controllerip",
        "bootp.option.vendor.alu.vid",
        "bootp.option.vendor.alu.tftp2",
        "bootp.option.vendor.alu.tftp1",
        "bootp.option.vendor.alu.suboption",
        "bootp.option.vendor.alu.sip_url",
        "bootp.option.vendor.alu.padding",
        "bootp.option.vendor.alu.end",
        "bootp.option.vendor.alu.app_type",
        "bootp.option.value.uint",
        "bootp.option.value.string",
        "bootp.vendor_specific_options",
        "bootp.vendor.suboption",
        "bootp.vendor.pktc.mtacap_len",
        "bootp.vendor.pktc.mta_cap_type",
        "bootp.vendor.pktc.mta_cap_len",
        "bootp.vendor.pktc.mdc_ietf.mib.signaling",
        "bootp.vendor.pktc.mdc_ietf.mib.reserved",
        "bootp.vendor.pktc.mdc_ietf.mib.mta",
        "bootp.vendor.pktc.mdc_ietf.mib.management_event",
        "bootp.vendor.pktc.mdc_euro.mib.signaling_extension",
        "bootp.vendor.pktc.mdc_euro.mib.signaling",
        "bootp.vendor.pktc.mdc_euro.mib.reserved",
        "bootp.vendor.pktc.mdc_euro.mib.mta_extension",
        "bootp.vendor.pktc.mdc_euro.mib.mta",
        "bootp.vendor.pktc.mdc_euro.mib.mem_extention",
        "bootp.vendor.pktc.mdc_euro.mib.management_event",
        "bootp.vendor.pktc.mdc_cl.mib.signaling_extension",
        "bootp.vendor.pktc.mdc_cl.mib.signaling",
        "bootp.vendor.pktc.mdc_cl.mib.reserved",
        "bootp.vendor.pktc.mdc_cl.mib.mta_extension",
        "bootp.vendor.pktc.mdc_cl.mib.mta",
        "bootp.vendor.pktc.mdc_cl.mib.mem_extention",
        "bootp.vendor.pktc.mdc_cl.mib.management_event",
        "bootp.vendor.pktc.mdc.supp_flow.secure",
        "bootp.vendor.pktc.mdc.supp_flow.hybrid",
        "bootp.vendor.pktc.mdc.supp_flow.basic",
        "bootp.vendor.pc.ietf_ccc.suboption",
        "bootp.vendor.pc.i05_ccc.suboption",
        "bootp.vendor.docsis.cmcap_len",
        "bootp.vendor.docsis.cm_cap_len",
        "bootp.vendor.data",
        "bootp.vendor.alu.vid",
        "bootp.vendor.alu.tftp2",
        "bootp.vendor.alu.tftp1",
        "bootp.vendor.alu.sip_url",
        "bootp.vendor.alu.app_type",
        "bootp.vendor",
        "bootp.type",
        "bootp.suboption_invalid",
        "bootp.subopt.unknown_type",
        "bootp.server_name_overloaded_by_dhcp",
        "bootp.server",
        "bootp.secs_le",
        "bootp.secs",
        "bootp.option.xwindows_system_font_server",
        "bootp.option.xwindows_system_display_manager",
        "bootp.option.vi_class.length",
        "bootp.option.vi_class.enterprise",
        "bootp.option.vi_class.data",
        "bootp.option.vi_class.cl_address_mode",
        "bootp.option.vi.value.uint",
        "bootp.option.vi.value.string",
        "bootp.option.vi.value.address",
        "bootp.option.vi.value",
        "bootp.option.vi.tr111.suboption",
        "bootp.option.vi.tr111.gateway_serial_number",
        "bootp.option.vi.tr111.gateway_product_class",
        "bootp.option.vi.tr111.gateway_manufacturer_oui",
        "bootp.option.vi.tr111.device_serial_number",
        "bootp.option.vi.tr111.device_product_class",
        "bootp.option.vi.tr111.device_manufacturer_oui",
        "bootp.option.vi.length",
        "bootp.option.vi.enterprise",
        "bootp.option.vi.cl.tftp_server_addresses",
        "bootp.option.vi.cl.suboption",
        "bootp.option.vi.cl.option_request",
        "bootp.option.vi.cl.modem_capabilities",
        "bootp.option.vi.cl.erouter_container_option",
        "bootp.option.vendor_class_id",
        "bootp.option.vendor_class_data",
        "bootp.option.vendor.value.uint",
        "bootp.option.vendor.value.string",
        "bootp.option.vendor.value.address",
        "bootp.option.vendor.value",
        "bootp.option.vendor.pxeclient.suboption",
        "bootp.option.vendor.pxeclient.padding",
        "bootp.option.vendor.pxeclient.multicast_address_alloc",
        "bootp.option.vendor.pxeclient.multicast_address",
        "bootp.option.vendor.pxeclient.mtftp_timeout",
        "bootp.option.vendor.pxeclient.mtftp_server_port",
        "bootp.option.vendor.pxeclient.mtftp_ip",
        "bootp.option.vendor.pxeclient.mtftp_delay",
        "bootp.option.vendor.pxeclient.mtftp_client_port",
        "bootp.option.vendor.pxeclient.menu_prompt",
        "bootp.option.vendor.pxeclient.end",
        "bootp.option.vendor.pxeclient.discovery_control",
        "bootp.option.vendor.pxeclient.credential_types",
        "bootp.option.vendor.pxeclient.boot_servers",
        "bootp.option.vendor.pxeclient.boot_menu",
        "bootp.option.vendor.pxeclient.boot_item",
        "bootp.option.vendor.cl.video_security_tape",
        "bootp.option.vendor.cl.vendor_name51",
        "bootp.option.vendor.cl.vendor_name10",
        "bootp.option.vendor.cl.suboption_request_list",
        "bootp.option.vendor.cl.suboption",
        "bootp.option.vendor.cl.software_version",
        "bootp.option.vendor.cl.serial_number",
        "bootp.option.vendor.cl.padding",
        "bootp.option.vendor.cl.oui_string",
        "bootp.option.value.int",
        "bootp.option.value.bool",
        "bootp.option.value.address",
        "bootp.option.value",
        "bootp.option.user_class.text",
        "bootp.option.user_class.malformed",
        "bootp.option.user_class.length",
        "bootp.option.user_class.data",
        "bootp.option.user_class",
        "bootp.option.tz_tcode",
        "bootp.option.tz_pcode",
        "bootp.option.type",
        "bootp.option.trailer_encapsulation",
        "bootp.option.time_server",
        "bootp.option.time_offset",
        "bootp.option.tftp_server_name",
        "bootp.option.tftp_server_address",
        "bootp.option.tcp_keepalive_interval",
        "bootp.option.tcp_keepalive_garbage",
        "bootp.option.tcp_default_ttl",
        "bootp.option.swap_server",
        "bootp.option.suboption_length",
        "bootp.option.subnet_selection_option",
        "bootp.option.subnet_mask",
        "bootp.option.streettalk_server",
        "bootp.option.streettalk_da_server",
        "bootp.option.static_route.router",
        "bootp.option.static_route.ip",
        "bootp.option.smtp_server",
        "bootp.option.slp_service_scope.value",
        "bootp.option.slp_service_scope.string",
        "bootp.option.slp_directory_agent.value",
        "bootp.option.slp_directory_agent.slpda_address",
        "bootp.option.sip_server_address.encoding",
        "bootp.option.sip_server.rfc_3396_detected",
        "bootp.option.sip_server.refer_last_option",
        "bootp.option.sip_server.name",
        "bootp.option.sip_server.encoding",
        "bootp.option.sip_server.address.stringz",
        "bootp.option.sip_server.address",
        "bootp.option.router_solicitation_address",
        "bootp.option.router",
        "bootp.option.root_path",
        "bootp.option.rfc3825.longitude_res",
        "bootp.option.rfc3825.longitude",
        "bootp.option.rfc3825.latitude_res",
        "bootp.option.rfc3825.latitude",
        "bootp.option.rfc3825.error",
        "bootp.option.rfc3825.altitude_type",
        "bootp.option.rfc3825.altitude",
        "bootp.option.rfc3825.altitide_res",
        "bootp.option.resource_location_server",
        "bootp.option.requested_ip_address",
        "bootp.option.request_list_item",
        "bootp.option.renewal_time_value",
        "bootp.option.rebinding_time_value",
        "bootp.option.rdnss.secondary_dns",
        "bootp.option.rdnss.reserved",
        "bootp.option.rdnss.primary_dns",
        "bootp.option.rdnss.preference",
        "bootp.option.rdnss.domain",
        "bootp.option.quotes_server",
        "bootp.option.pxe_path_prefix",
        "bootp.option.pxe_config_file",
        "bootp.option.private_proxy_autodiscovery",
        "bootp.option.portparams.psid_length",
        "bootp.option.portparams.psid",
        "bootp.option.portparams.offset",
        "bootp.option.pop3_server",
        "bootp.option.policy_filter.subnet_mask",
        "bootp.option.policy_filter.ip",
        "bootp.option.perform_router_discover",
        "bootp.option.perform_mask_discovery",
        "bootp.option.pcp.server",
        "bootp.option.pcp.list_length",
        "bootp.option.path_mtu_plateau_table_item",
        "bootp.option.path_mtu_aging_timeout",
        "bootp.option.parse_err",
        "bootp.option.padding",
        "bootp.option.option_overload.sname_end_missing",
        "bootp.option.option_overload.file_end_missing",
        "bootp.option.option_overload",
        "bootp.option.option.vi.cl.tag_unknown",
        "bootp.option.ntp_server",
        "bootp.option.novell_options.value.uint",
        "bootp.option.novell_options.value.bool",
        "bootp.option.novell_options.value.address",
        "bootp.option.novell_options.value",
        "bootp.option.novell_options.support_netware_v1_1",
        "bootp.option.novell_options.suboption",
        "bootp.option.novell_options.primary_dss",
        "bootp.option.novell_options.preferred_dss_server",
        "bootp.option.novell_options.nearest_nwip_server",
        "bootp.option.novell_options.broadcast",
        "bootp.option.novell_options.autoretry_delay",
        "bootp.option.novell_options.autoretries",
        "bootp.option.novell_netware_ip_domain",
        "bootp.option.novell_dss.string",
        "bootp.option.novell_dss.ip",
        "bootp.option.novell_ds_tree_name",
        "bootp.option.novell_ds_context",
        "bootp.option.nonstd_data",
        "bootp.option.non_local_source_routing",
        "bootp.option.nntp_server",
        "bootp.option.nis_server",
        "bootp.option.nis_plus_server",
        "bootp.option.nis_plus_domain",
        "bootp.option.nis_domain",
        "bootp.option.netinfo_parent_server_tag",
        "bootp.option.netinfo_parent_server_address",
        "bootp.option.netbios_over_tcpip_scope",
        "bootp.option.netbios_over_tcpip_node_type",
        "bootp.option.netbios_over_tcpip_name_server",
        "bootp.option.netbios_over_tcpip_dd_name_server",
        "bootp.option.name_server",
        "bootp.option.mudurl",
        "bootp.option.mobile_ip_home_agent",
        "bootp.option.message",
        "bootp.option.merit_dump_file",
        "bootp.option.max_datagram_reassembly_size",
        "bootp.option.mask_supplier",
        "bootp.option.lpr_server",
        "bootp.option.lost_server_domain_name",
        "bootp.option.log_server",
        "bootp.option.length",
        "bootp.option.isns.server_security_bitmap.tunnel_mode",
        "bootp.option.isns.server_security_bitmap.transport_mode",
        "bootp.option.isns.server_security_bitmap.reserved",
        "bootp.option.isns.server_security_bitmap.pfs",
        "bootp.option.isns.server_security_bitmap.main_mode",
        "bootp.option.isns.server_security_bitmap.ike_ipsec_enabled",
        "bootp.option.isns.server_security_bitmap.enabled",
        "bootp.option.isns.server_security_bitmap.aggressive_mode",
        "bootp.option.isns.server_security_bitmap",
        "bootp.option.isns.secondary_server_addr",
        "bootp.option.isns.primary_server_addr",
        "bootp.option.isns.ignored_bitfield",
        "bootp.option.isns.heartbeat_originator_addr",
        "bootp.option.isns.functions.sec_policy_distribution",
        "bootp.option.isns.functions.reserved",
        "bootp.option.isns.functions.enabled",
        "bootp.option.isns.functions.dd_base_authorization",
        "bootp.option.isns.functions",
        "bootp.option.isns.discovery_domain_access_control.node",
        "bootp.option.isns.discovery_domain_access.reserved",
        "bootp.option.isns.discovery_domain_access.iscsi_target",
        "bootp.option.isns.discovery_domain_access.iscsi_initiator",
        "bootp.option.isns.discovery_domain_access.initiator_target_port",
        "bootp.option.isns.discovery_domain_access.ifcp_target_port",
        "bootp.option.isns.discovery_domain_access.enabled",
        "bootp.option.isns.discovery_domain_access",
        "bootp.option.isns.administrative_flags.reserved",
        "bootp.option.isns.administrative_flags.management_scns",
        "bootp.option.isns.administrative_flags.heartbeat",
        "bootp.option.isns.administrative_flags.enabled",
        "bootp.option.isns.administrative_flags.default_discovery_domain",
        "bootp.option.isns.administrative_flags",
        "bootp.option.ip_forwarding",
        "bootp.option.ip_address_lease_time",
        "bootp.option.interface_mtu",
        "bootp.option.impress_server",
        "bootp.option.hostname",
        "bootp.option.forcerenew_nonce.algorithm",
        "bootp.option.extension_path",
        "bootp.option.ethernet_encapsulation",
        "bootp.option.enterprise.malformed",
        "bootp.option.end",
        "bootp.option.domain_name_server",
        "bootp.option.domain_name",
        "bootp.option.dhcp_server_id",
        "bootp.option.dhcp_name_service_search_option",
        "bootp.option.dhcp_name_service.invalid",
        "bootp.option.dhcp_max_message_size",
        "bootp.option.dhcp_dns_domain_search_list_rfc_3396_detected",
        "bootp.option.dhcp_dns_domain_search_list_refer_last_option",
        "bootp.option.dhcp_dns_domain_search_list_fqdn",
        "bootp.option.dhcp_auto_configuration",
        "bootp.option.dhcp_authentication.secret_id",
        "bootp.option.dhcp_authentication.rdm_replay_detection",
        "bootp.option.dhcp_authentication.rdm_rdv",
        "bootp.option.dhcp_authentication.rdm",
        "bootp.option.dhcp_authentication.protocol",
        "bootp.option.dhcp_authentication.information",
        "bootp.option.dhcp_authentication.hmac_md5_hash",
        "bootp.option.dhcp_authentication.algorithm",
        "bootp.option.dhcp_authentication.alg_delay",
        "bootp.option.dhcp",
        "bootp.option.default_www_server",
        "bootp.option.default_irc_server",
        "bootp.option.default_ip_ttl",
        "bootp.option.default_finger_server",
        "bootp.option.client_system_architecture",
        "bootp.option.client_last_transaction_time",
        "bootp.option.classless_static_route.",
        "bootp.option.classless_static_route",
        "bootp.option.classless_static.route",
        "bootp.option.cl_dss_id.option",
        "bootp.option.cl_dss_id.len",
        "bootp.option.cl_dss_id",
        "bootp.option.civic_location.what",
        "bootp.option.civic_location.country",
        "bootp.option.civic_location.ca_value",
        "bootp.option.civic_location.ca_type",
        "bootp.option.civic_location.ca_length",
        "bootp.option.civic_location.bad_cattype",
        "bootp.option.capwap_access_controller",
        "bootp.option.captive_portal",
        "bootp.option.bulk_lease.status_code_message",
        "bootp.option.bulk_lease.status_code",
        "bootp.option.bulk_lease.start_time_of_state",
        "bootp.option.bulk_lease.query_start_time",
        "bootp.option.bulk_lease.query_end_time",
        "bootp.option.bulk_lease.dhcp_state",
        "bootp.option.bulk_lease.data_source",
        "bootp.option.bulk_lease.base_time",
        "bootp.option.broadcast_address",
        "bootp.option.bootfile_name",
        "bootp.option.boot_file_size",
        "bootp.option.associated_ip_option",
        "bootp.option.arp_cache_timeout",
        "bootp.option.andsf_server",
        "bootp.option.all_subnets_are_local",
        "bootp.option.agent_information_option.vrf_name_vpn_id_oui",
        "bootp.option.agent_information_option.vrf_name_vpn_id_index",
        "bootp.option.agent_information_option.vrf_name_vpn_id",
        "bootp.option.agent_information_option.vrf_name.vpn_id.oui",
        "bootp.option.agent_information_option.vrf_name.vpn_id.index",
        "bootp.option.agent_information_option.vrf_name.vpn_id",
        "bootp.option.agent_information_option.vrf_name.global",
        "bootp.option.agent_information_option.vrf_name",
        "bootp.option.agent_information_option.vi.enterprise",
        "bootp.option.agent_information_option.vi.data_length",
        "bootp.option.agent_information_option.vi.cl.tag_length",
        "bootp.option.agent_information_option.vi.cl.tag",
        "bootp.option.agent_information_option.vi.cl.option",
        "bootp.option.agent_information_option.vi.cl.length",
        "bootp.option.agent_information_option.vi.cl.docsis_version",
        "bootp.option.agent_information_option.vi",
        "bootp.option.agent_information_option.value.uint",
        "bootp.option.agent_information_option.value.string",
        "bootp.option.agent_information_option.value.address",
        "bootp.option.agent_information_option.value",
        "bootp.option.agent_information_option.subscriber_id",
        "bootp.option.agent_information_option.suboption",
        "bootp.option.agent_information_option.server_id_override_cisco",
        "bootp.option.agent_information_option.server_id_override",
        "bootp.option.agent_information_option.reserved",
        "bootp.option.agent_information_option.relay_agent_id",
        "bootp.option.agent_information_option.radius_attributes",
        "bootp.option.agent_information_option.padding",
        "bootp.option.agent_information_option.link_selection_cisco",
        "bootp.option.agent_information_option.link_selection",
        "bootp.option.agent_information_option.flags",
        "bootp.option.agent_information_option.docsis_device_class",
        "bootp.option.agent_information_option.authentication",
        "bootp.option.agent_information_option.agent_remote_id",
        "bootp.option.agent_information_option.agent_circuit_id",
        "bootp.option.6RD.prefix_len",
        "bootp.option.6RD.prefix",
        "bootp.option.6RD.malformed",
        "bootp.option.6RD.ipv4_mask_len",
        "bootp.option.6RD.border_relay_ip",
        "bootp.missing_subopt_value",
        "bootp.missing_subopt_length",
        "bootp.malformed.duid",
        "bootp.ip.your",
        "bootp.ip.server",
        "bootp.ip.relay",
        "bootp.ip.client",
        "bootp.id",
        "bootp.hw.type",
        "bootp.hw.mac_addr",
        "bootp.hw.len",
        "bootp.hw.addr_padding",
        "bootp.hw.addr",
        "bootp.hops",
        "bootp.fqdn.s",
        "bootp.fqdn.rcode2",
        "bootp.fqdn.rcode1",
        "bootp.fqdn.o",
        "bootp.fqdn.name",
        "bootp.fqdn.n",
        "bootp.fqdn.mbz",
        "bootp.fqdn.flags",
        "bootp.fqdn.e",
        "bootp.flags.reserved",
        "bootp.flags.bc",
        "bootp.flags",
        "bootp.file",
        "bootp.end_option_missing",
        "bootp.docsis_cm_cap_type",
        "bootp.docsis_cm_cap.ussymrate.640",
        "bootp.docsis_cm_cap.ussymrate.5120",
        "bootp.docsis_cm_cap.ussymrate.320",
        "bootp.docsis_cm_cap.ussymrate.2560",
        "bootp.docsis_cm_cap.ussymrate.160",
        "bootp.docsis_cm_cap.ussymrate.1280",
        "bootp.docsis_cm_cap.ranging_hold_off.eps",
        "bootp.docsis_cm_cap.ranging_hold_off.emta",
        "bootp.docsis_cm_cap.ranging_hold_off.dsg",
        "bootp.docsis_cm_cap.ranging_hold_off.cm",
        "bootp.docsis_cm_cap.mpls.tc",
        "bootp.docsis_cm_cap.mpls.svid",
        "bootp.docsis_cm_cap.mpls.stpid",
        "bootp.docsis_cm_cap.mpls.stci",
        "bootp.docsis_cm_cap.mpls.spcp",
        "bootp.docsis_cm_cap.mpls.sdei",
        "bootp.docsis_cm_cap.mpls.label",
        "bootp.docsis_cm_cap.mpls.iuca",
        "bootp.docsis_cm_cap.mpls.itpid",
        "bootp.docsis_cm_cap.mpls.itci",
        "bootp.docsis_cm_cap.mpls.isid",
        "bootp.docsis_cm_cap.mpls.ipcp",
        "bootp.docsis_cm_cap.mpls.idei",
        "bootp.docsis_cm_cap.mpls.cvid",
        "bootp.docsis_cm_cap.mpls.ctpid",
        "bootp.docsis_cm_cap.mpls.ctci",
        "bootp.docsis_cm_cap.mpls.cpcp",
        "bootp.docsis_cm_cap.mpls.ccfi",
        "bootp.docsis_cm_cap.mpls.bvid",
        "bootp.docsis_cm_cap.mpls.btpid",
        "bootp.docsis_cm_cap.mpls.btci",
        "bootp.docsis_cm_cap.mpls.bsa",
        "bootp.docsis_cm_cap.mpls.bpcp",
        "bootp.docsis_cm_cap.mpls.bdei",
        "bootp.docsis_cm_cap.mpls.bda",
        "bootp.dhcp",
        "bootp.cookie",
        "bootp.client_network_id_minor",
        "bootp.client_network_id_major",
        "bootp.client_id_uuid",
        "bootp.client_id_duid_llt_hw_type",
        "bootp.client_id_duid_ll_hw_type",
        "bootp.client_id.uuid",
        "bootp.client_id.undef",
        "bootp.client_id.type",
        "bootp.client_id.time",
        "bootp.client_id.link_layer_address",
        "bootp.client_id.iaid",
        "bootp.client_id.enterprise_num",
        "bootp.client_id.duid_type",
        "bootp.client_id.duid_llt_hw_type",
        "bootp.client_id.duid_ll_hw_type",
        "bootp.client_id",
        "bootp.client_hardware_address",
        "bootp.client_address_not_given",
        "bootp.cl.ietf_ccc.dev_realm_unc_key_nom_timeout",
        "bootp.cl.ietf_ccc.dev_realm_unc_key_max_timeout",
        "bootp.cl.ietf_ccc.dev_realm_unc_key_max_retries",
        "bootp.cl.ietf_ccc.dev_prov_unc_key_nom_timeout",
        "bootp.cl.ietf_ccc.dev_prov_unc_key_max_timeout",
        "bootp.cl.ietf_ccc.dev_prov_unc_key_max_retries",
        "bootp.ccc.ietf.sec_tkt.pc_provision_server",
        "bootp.ccc.ietf.sec_tkt.all_pc_call_management",
        "bootp.boot_filename_overloaded_by_dhcp",
        "bootp.bad_length",
        "bootp.bad_bitfield",

    ]
    for u in unsed:
        if u in features:
            features.remove(u)
    
    return features

def get_tshark_valid_http_protocol_feature_list():
    features = get_numeric_features('http')
    unsed = [
       "http.ssl_port",
       "http.chunkd_and_length",
    ]
    for u in unsed:
        if u in features:
            features.remove(u)
    
    return features


def get_tshark_valid_udp_protocol_feature_list():
    features = get_numeric_features('udp')
    unsed = [
        "udp.checksum_good",
        "udp.checksum_coverage.expert",
        "udp.checksum_bad.expert",
        "udp.checksum_bad",
    ]
    for u in unsed:
        if u in features:
            features.remove(u)
    
    return features


def get_tshark_valid_eapol_protocol_feature_list():
    features = get_numeric_features('eapol')
    unsed = [
        "eapol.keydes.keylen",
        "eapol.keydes.key_info.keydes_version",
        "eapol.keydes.key_info.keydes_ver",
        "eapol.keydes.key_info.key_index",
        "eapol.keydes.key_info",
        "eapol.keydes.index.indexnum",
        "eapol.keydes.datalen",
        "eapol.keydes.data_len",
        "eapol.keydes.rsc",
        "eapol.keydes.nonce",
        "eapol.keydes.mic",
        "eapol.keydes.key_info.secure",
        "eapol.keydes.key_info.request",
        "eapol.keydes.key_info.key_type",
        "eapol.keydes.key_info.key_mic",
        "eapol.keydes.key_info.key_ack",
        "eapol.keydes.key_info.install",
        "eapol.keydes.key_info.error",
        "eapol.keydes.key_info.encrypted_key_data",
        "eapol.keydes.key_info.encr_key_data",
        "eapol.keydes.index.keytype",
        "eapol.keydes.id",
        "eapol.keydes.data",

    ]
    for u in unsed:
        if u in features:
            features.remove(u)
    
    return features



def get_tshark_valid_icmpv6_protocol_feature_list():
    features = get_numeric_features('icmpv6')
    unsed = [
        "icmpv6.rpl.secure.algorithm.signature",
        "icmpv6.rpl.secure.algorithm.encryption",
        "icmpv6.ra.router_lifetime",
        "icmpv6.ra.retrans_timer",
        "icmpv6.ra.reachable_time",
        "icmpv6.ra.cur_hop_limit",
        "icmpv6.option.type",
        "icmpv6.option.name_type",
        "icmpv6.option.length",
        "icmpv6.option.cga.pad_length",
        "icmpv6.opt_prefix.length",
        "icmpv6.opt_prefix.flag.reserved",
        "icmpv6.opt.abro.version",
        "icmpv6.nor",
        "icmpv6.identifier",
        "icmpv6.comp",
        "icmpv6.all_comp",
        "icmpv6_x509_Certificate",
        "icmpv6.recursive_dns_serv",
        "icmpv6.option.rsa.key_hash",
        "icmpv6.option.name_x501",
        "icmpv6.option.name_type.fqdn",
        "icmpv6.option.cga.subnet_prefix",
        "icmpv6.option.cga.modifier",
        "icmpv6.option.cga.ext_type",
        "icmpv6.option.cga.ext_length",
        "icmpv6.option.cga.count",
        "icmpv6.option.cga",
        "icmpv6.option",
        "icmpv6.opt_prefix.flag.l",
        "icmpv6.opt_prefix.flag.a",
        "icmpv6.ni.query.node_name",
        "icmpv6.ni.query.node_address",
        "icmpv6.ni.query.ipv4_address",
        "icmpv6.haad.ha_addrs",
        "icmpv6.checksum_bad",

        
    ]
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features

def get_tshark_valid_tcp_protocol_feature_list():
    features = get_numeric_features('tcp')
    
    unsed = ["tcp.options.timestamp.tsval.syncookie.sack",
            "tcp.options.timestamp.tsval.syncookie.ecn",
            "tcp.options.time_stamp",
            "tcp.options.tarr.rate",
            "tcp.options.experimental.magic_number",
            "tcp.options.tar.reserved",
            "tcp.options.scpsflags.reserved3",
            "tcp.options.scpsflags.reserved2",
            "tcp.options.scpsflags.reserved1",
            "tcp.options.rvbd.probe.len",
            "tcp.options.mptcp.sendtruncmac",
            "tcp.options.mptcp.sendmac",
            "tcp.options.mptcp.dataseqno",
            "tcp.options.mptcp.dataack",
            "tcp.options.mood_val",
            "tcp.options.mood",
            "tcp.options.experimental.exid",
            "tcp.options.echo_reply",
            "tcp.options.acc_ecn.ee1b",
            "tcp.options.acc_ecn.ee0b",
            "tcp.options.acc_ecn.eceb",
            "tcp.non_zero_bytes_after_eol",
            "tcp.flags.ece",
            "tcp.flags.ae",
            "tcp.flags.ace",
            "tcp.data",
            "tcp.connection.sack",
            "tcp.checksum_good",
            "tcp.checksum_bad",
            "mptcp.analysis.unsupported_algorithm",
            "mptcp.analysis.unexpected_idsn",
            "mptcp.analysis.missing_algorithm",
            "tcp.options.timestamp.tsval.syncookie.timestamp",
            "tcp.options.timestamp.tsval.syncookie.ecn",
            "tcp.options.tar.reserved",
            "tcp.options.timestamp.tsval.syncookie.wscale",
            "tcp.syncookie.time",
            "tcp.syncookie.mss",
            "tcp.syncookie.hash",
            "tcp.options.wscale_val",
            "tcp.options.type.number",
            "tcp.options.type.class",
            "tcp.options.type",
            "mptcp.analysis.echoed_key_mismatch",
            "tcp.options.type.copy",
            "tcp.flags.ns",
            "tcp.flags.ecn",
            "tcp.analysis.echoed_key_mismatch"]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features

def get_tshark_valid_tls_protocol_feature_list():
    features = get_numeric_features('tls')
    
    unsed = [
        "tls.quic.supported_versions.len",
        "tls.quic.supported_versions",
        "tls.quic.parameter.vi.other_version",
        "tls.quic.parameter.vi.chosen_version",
        "tls.quic.parameter.preferred_address.ipversion",
        "tls.quic.parameter.preferred_address.ipaddress.length",
        "tls.quic.parameter.max_packet_size",
        "tls.quic.parameter.idle_timeout",
        "tls.quic.parameter.cibir_encoding.offset",
        "tls.quic.parameter.cibir_encoding.length",
        "tls.quic.negotiated_version",
        "tls.quic.initial_version",
        "tls.quic.parameter.vn.supported_version_count",
        "tls.quic.parameter.vn.supported_version",
        "tls.quic.parameter.vn.received_negotiation_version_count",
        "tls.quic.parameter.vn.received_negotiation_version",
        "tls.quic.parameter.vn.previously_attempted_version",
        "tls.quic.parameter.vn.negotiated_version",
        "tls.quic.parameter.vn.currently_attempted_version",
        "tls.quic.parameter.vn.compatible_version_count",
        "tls.quic.parameter.vn.compatible_version",
        "tls.quic.parameter.ocid",

    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_arp_protocol_feature_list():
    features = get_numeric_features('arp')
    
    # unsed = ["tcp.options.timestamp.tsval.syncookie.sack",
    #         "tcp.options.timestamp.tsval.syncookie.ecn",
    #         "tcp.options.time_stamp",
    #         "tcp.options.tarr.rate",
    #         "tcp.options.tar.reserved",
    #         "tcp.options.scpsflags.reserved3",
    #         "tcp.options.scpsflags.reserved2",
    #         "tcp.options.scpsflags.reserved1",
    #         "tcp.options.rvbd.probe.len",
    #         "tcp.options.mptcp.sendtruncmac",
    #         "tcp.options.mptcp.sendmac",
    #         "tcp.options.mptcp.dataseqno",
    #         "tcp.options.mptcp.dataack",
    #         "tcp.options.mood_val",
    #         "tcp.options.mood",
    #         "tcp.options.experimental.exid",
    #         "tcp.options.echo_reply",
    #         "tcp.options.acc_ecn.ee1b",
    #         "tcp.options.acc_ecn.ee0b",
    #         "tcp.options.acc_ecn.eceb",
    #         "tcp.non_zero_bytes_after_eol",
    #         "tcp.flags.ece",
    #         "tcp.flags.ae",
    #         "tcp.flags.ace",
    #         "tcp.data",
    #         "tcp.connection.sack",
    #         "tcp.checksum_good",
    #         "tcp.checksum_bad",
    #         "mptcp.analysis.unsupported_algorithm",
    #         "mptcp.analysis.unexpected_idsn",
    #         "mptcp.analysis.missing_algorithm",
    #         "tcp.options.timestamp.tsval.syncookie.timestamp",
    #         "tcp.options.timestamp.tsval.syncookie.ecn",
    #         "tcp.options.tar.reserved",
    #         "tcp.options.timestamp.tsval.syncookie.wscale",
    #         "tcp.syncookie.time",
    #         "tcp.syncookie.mss",
    #         "tcp.syncookie.hash",
    #         "tcp.options.wscale_val",
    #         "tcp.options.type.number",
    #         "tcp.options.type.class",
    #         "tcp.options.type",
    #         "mptcp.analysis.echoed_key_mismatch",
    #         "tcp.analysis.echoed_key_mismatch"]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features


def get_tshark_valid_dhcp_protocol_feature_list():
    features = get_numeric_features('dhcp')
    
    unsed = [
        "dhcp.option.agent_information_option.vi.cl.dpoe_system_version",
        "dhcp.vendor.pktc.mdc_euro.mib.mem_extention",
        "dhcp.vendor.pktc.mdc_cl.mib.mem_extention",
        "dhcp.option.rfc3825.altitide_res",
        "dhcp.option.agent_information_option.vi.cl.tag_length",
        "dhcp.option.agent_information_option.vi.cl.tag",
        "dhcp.option.agent_information_option.vi.cl.option",
        "dhcp.option.agent_information_option.vi.cl.length",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_coap_protocol_feature_list():
    features = get_numeric_features('coap')
    
    unsed = [
        "coap.tid",
        "coap.optcount",
        "coap.opt.subscr_lifetime",
        "coap.opt.jump",
        "coap.ocount",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_data_protocol_feature_list():
    features = get_numeric_features('data')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features

def get_tshark_valid_dns_protocol_feature_list():
    features = get_numeric_features('dns')
    
    unsed = [
        "hf.dns.apl.coded.prefix",
        "dns.t_key.flags.signatory",
        "dns.t_key.flags",
        "dns.soa.mininum_ttl",
        "dns.rr.opt.len",
        "dns.rr.opt.code",
        "dns.rr.opt.client.scope",
        "dns.rr.opt.client.netmask",
        "dns.rr.opt.client.family",
        "dns.resp.udp_payload_size",
        "dns.loc.vertial_precision",
        "dns.extraneous.length",
        "dns.apl.coded.prefix",
        "dns.ttl.negative",
        "dns.t_key.flags.required",
        "dns.t_key.flags.mime",
        "dns.t_key.flags.ipsec",
        "dns.t_key.flags.confidentiality",
        "dns.t_key.flags.authentication",
        "dns.t_key.flags.associated_user"
        "dns.t_key.flags.associated_named_entity",
        "dns.svcb.svcparams",
        "dns.svcb.svcparam.echoconfig",
        "dns.rr.opt.data",
        "dns.rr.opt.client.addr6",
        "dns.rr.opt.client.addr4",
        "dns.rr.opt.client.addr",
        "dns.rr.opt",
        "dns.resp.primaryname",
        "dns.resp.ns",
        "dns.resp.addr",
        "dns.t_key.flags.associated_user",
        "dns.t_key.flags.associated_named_entity",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features



def get_tshark_valid_eth_protocol_feature_list():
    features = get_numeric_features('eth')
    
    unsed = [
        "eth.vlan.tpid",
        "eth.vlan.pri",
        "eth.vlan.id",
        "eth.vlan.cfi",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features



def get_tshark_valid_ethertype_protocol_feature_list():
    features = get_numeric_features('ethertype')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features




def get_tshark_valid_icmp_protocol_feature_list():
    features = get_numeric_features('icmp')
    
    unsed = [
        "icmp.mpls.version",
        "icmp.mpls.res",
        "icmp.mpls.length",
        "icmp.mpls.ctype",
        "icmp.mpls.class",
        "icmp.mpls.checksum",
        "icmp.mpls.checksum_bad",
        "icmp.mpls",
        "icmp.int_info.ip",
        "icmp.checksum_bad.expert",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features



def get_tshark_valid_ip_protocol_feature_list():
    features = get_numeric_features('ip')
    
    unsed = [
        "ip.dsfield.ect",
        "ip.dsfield.ce",
        "ip.geoip.src_isp",
        "ip.geoip.isp",
        "ip.geoip.dst_isp",
        "ip.checksum_good",
        "ip.checksum_bad",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_llc_protocol_feature_list():
    features = get_numeric_features('llc')
    
    unsed = [
        "locamation-im.llc.pid",
        "llc.apple_pid",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_pkix1explicit_protocol_feature_list():
    features = get_numeric_features('pkix1explicit')
    
    unsed = [
        "pkix1explicit.RDNSequence_item",
        "pkix1explicit.asIdsOrRanges_item",
        "pkix1explicit.addressesOrRanges_item",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features

def get_tshark_valid_pkix1implicit_protocol_feature_list():
    features = get_numeric_features('pkix1implicit')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features





def get_tshark_valid_x509ce_protocol_feature_list():
    features = get_numeric_features('x509ce')
    
    unsed = [
        "x509ce.StatusReferrals_item",
        "x509ce.GeneralNames_item"
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_x509sat_protocol_feature_list():
    features = get_numeric_features('x509sat')
    
    unsed = [
        "x509sat.PostalAddress_item",
        "x509sat.or_item",
        "x509sat.CaseIgnoreListMatch_item",
        "x509sat.and_item",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features