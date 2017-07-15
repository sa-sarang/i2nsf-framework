#	!/usr/bin/env python
import urllib
import urllib2
import requests
import socket
import json
import MySQLdb #DB
import os
import xml.etree.ElementTree as etree
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element,SubElement, dump
from xml.etree import ElementTree
from xml.sax.saxutils import unescape
from xml.etree.ElementTree import ElementTree
from pprint import pprint

#------------------------------------------------------ #

import time, json;
import BaseHTTPServer;
from urlparse import urlparse, parse_qs

HOST_NAME = "localhost";
PORT_NUMBER = 9000;

NSFs = {};

def parse_to_yang(nsf_name, policy_name, rule):
	print("do parse action");



class RequestHandler (BaseHTTPServer.BaseHTTPRequestHandler):
	def do_HEAD(self):
		self.send_response(200);
		self.send_header("Content-type", "text/json");
		self.end_headers();

	def do_GET(self):
		"""Respond to a GET request"""

		url = self.path.split("?")[0];
		if(url == "/sc/ipc/config/"):
			query_components = parse_qs(urlparse(self.path).query)
			nsf_name = query_components["nsf_name"][0];
			policy_name = query_components["policy_name"][0];
			rule = query_components["rule"][0];

			response_code = 200;
			response_msg = "Successfully Configured";

			if(nsf_name in NSFs):
				
				if(policy_name in NSFs[nsf_name]):
					response_code = 100;
					response_msg = "Policy name already Exists";
				else:
					NSFs[nsf_name][policy_name] = {};
					NSFs[nsf_name][policy_name]["rule"] = rule;
			else:
				NSFs[nsf_name] = {};
				NSFs[nsf_name][policy_name] = {};
				NSFs[nsf_name][policy_name]["rule"] = rule;
			if nsf_name == "firewall":
				json_rule = json.loads(rule)[0];
				policy_id = json_rule['id']
				policy_name = json_rule['Policy_name']
				policy_position = json_rule['Position']
				policy_website = json_rule['Website']
				policy_start_time = json_rule['Start_time']
				policy_end_time = json_rule['End_time']
				policy_action = json_rule['Action']

				employee_ip_list = []	
				web_ip_list = []


			#======================DB Part========================
				str_exe_position = "select * from Policies2 where Position like '" + policy_position + "';"

				if policy_website == "Facebook":
					web_ip_list.append("31.13.68.35")
				else:
					print "NO"

				#str_exe_web = "select * from Policies3 where Web_Name like '" + policy_website + "';"

				#print(root[0][0].text)
				#print(root[0][1].text)
				#print(root[0][2].text)
				#print(root[0][3].text)
				#print(root[0][4].text)
				#print(root[0][5].text)
				#print(root[0][6].text)
				#print(Policy)
				#print(content)
				db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Position")
				cur = db.cursor()
				#if root[0][2].text == 'staff': 
				cur.execute(str_exe_position)
				for row in cur.fetchall():
					employee_ip_list.append(row[0])
			#       		print row[0]
				employee_ip_list_len = len(employee_ip_list)
				db.close()

				#print(employee_ip_list)

				#db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Web")
				#cur = db.cursor()
				#cur.execute(str_exe_web)
				#for row2 in cur.fetchall():
				#	web_ip_list.append(row2[0])

				#db.close()
				#print(web_ip_list)

			#======================Print Part========================
				
				print(policy_id)
				print(policy_name)
				print(employee_ip_list)
				print(employee_ip_list_len)
				print(web_ip_list)
				print(policy_start_time)
				print(policy_end_time)
				print(policy_action)


			#======================XML Part_1========================

				hello = Element("hello")
				hello.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0"
				to = Element("capabilities")
				
				capabilities = Element("capability")
				to.text = " " 
				
				capabilities.text = "urn:ietf:params:netconf:base:1.0"
				hello.append(to)	
				to.append(capabilities)
				
			#======================XML Part_2========================

				rpc = Element("rpc")
				rpc.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0" 
				rpc.attrib["message-id"] = "1"
				elem_edit_config = Element("edit-config")
				elem_target = Element("target")
				elem_config = Element("config")
				elem_policy = Element("policy")
				elem_policy.attrib["xmlns"]="http://skku.com/iot/example/ietf-i2nsf-capability-interface" 
				elem_policy.attrib["xmlns:nc"]="urn:ietf:params:xml:ns:netconf:base:1.0"
				elem_rules = Element("rules")
				elem_rules.attrib["nc:operation"]="create"
				elem_rule_id = Element("rule-id")
				elem_rule_name = Element("rule-name")
				# elem_rule_msg = Element("rule-msg")
				# elem_rule_rev = Element("rule-rev")
				# elem_rule_gid = Element("rule-gid")
				# elem_rule_class_type = Element("rule-class-type")
				# elem_rule_reference = Element("rule-reference")
				# elem_rule_priority = Element("rule-priority")
				elem_condition = Element("condition")
				elem_packet_sec_condition = Element("packet-security-condition")
				elem_packet_sec_ipv4 = Element("packet-security-ipv4-condition")
				elem_pkt_sec_cond_ipv4_src_addr = []

				# elem_pkt_sec_cond_ipv4_header_length=Element("pkt-sec-cond-ipv4-header-length")
				# elem_pkt_sec_cond_ipv4_tos=Element("pkt-sec-cond-ipv4-tos")
				# elem_pkt_sec_cond_ipv4_total_length=Element("pkt-sec-cond-ipv4-total-length")
				# elem_pkt_sec_cond_ipv4_id=Element("pkt-sec-cond-ipv4-id")
				# elem_pkt_sec_cond_ipv4_fragment=Element("pkt-sec-cond-ipv4-fragment")
				# elem_pkt_sec_cond_ipv4_offset=Element("pkt-sec-cond-ipv4-offset")
				# elem_pkt_sec_cond_ipv4_ttl=Element("pkt-sec-cond-ipv4-ttl")
				# elem_pkt_sec_cond_ipv4_protocol=Element("pkt-sec-cond-ipv4-protocol")

				for i in range(employee_ip_list_len):
					elem_pkt_sec_cond_ipv4_src_addr.append(Element("pkt-sec-cond-ipv4-src"))
				elem_pkt_sec_cond_ipv4_dest_addr = Element("pkt-sec-cond-ipv4-dest")

				elem_generic_context_condition = Element("generic-context-condition")
				elem_schedule = Element("schedule")
				elem_start_time = Element("start-time")
				elem_end_time = Element("end-time")
				elem_action = Element("action")
				elem_action_type = Element("action-type")
				elem_ingress_action = Element("ingress-action")
				elem_ingress_action_type=Element("ingress-action-type")
				elem_pass = Element("pass")
				elem_reject = Element("reject")
				elem_drop = Element("drop")
				elem_alert = Element("alert")


				elem_edit_config.text = " "
				temp_elem_target = Element("")
				temp_elem_target.text = "<running/>"
				temp_elem_target = ET.fromstring(temp_elem_target.text)

				elem_config.text = " "
				elem_rule_name.text = '%s' % (policy_name)
				elem_rule_id.text = '%s' % (policy_id) 

				#have to need input data, this is just example
				# elem_rule_msg.text="msg"
				# elem_rule_rev.text="14"
				# elem_rule_gid.text="44"
				# elem_rule_class_type.text="classtype"
				# elem_rule_reference.text="reference"
				# elem_rule_priority.text="1"

				elem_condition.text = " "
				elem_packet_sec_condition.text = " "
				elem_packet_sec_ipv4.text = " "
				elem_pkt_sec_cond_ipv4_dest_addr.text = '%s' % (web_ip_list[0])
				elem_generic_context_condition.text = " "
				elem_schedule.text = " "
				elem_start_time.text = '%s' % (policy_start_time)
				elem_end_time.text = '%s' % (policy_end_time)
				elem_action.text = " "
				elem_action_type.text = " "
				elem_ingress_action.text = " "

				if 'Block' in policy_action :
					elem_reject.text = "true"
				else :
					elem_pass.text = "true"


				rpc.append(elem_edit_config)
				elem_edit_config.append(elem_target)
				elem_target.append(temp_elem_target)
				elem_edit_config.append(elem_config)
				elem_config.append(elem_policy)
				elem_policy.append(elem_rules)
				elem_rules.append(elem_rule_id)
				elem_rules.append(elem_rule_name)
				# elem_rules.append(elem_rule_msg)
				# elem_rules.append(elem_rule_rev)
				# elem_rules.append(elem_rule_gid)
				# elem_rules.append(elem_rule_class_type)
				# elem_rules.append(elem_rule_reference)
				# elem_rules.append(elem_rule_priority)
				elem_rules.append(elem_condition)

				elem_condition.append(elem_packet_sec_condition)
				elem_packet_sec_condition.append(elem_packet_sec_ipv4)

				for i in range(employee_ip_list_len):
					elem_pkt_sec_cond_ipv4_src_addr[i].text = '%s' % (employee_ip_list[i])
					elem_packet_sec_ipv4.append(elem_pkt_sec_cond_ipv4_src_addr[i])
				elem_packet_sec_ipv4.append(elem_pkt_sec_cond_ipv4_dest_addr)

				elem_condition.append(elem_generic_context_condition)
				elem_generic_context_condition.append(elem_schedule)
				elem_schedule.append(elem_start_time)
				elem_schedule.append(elem_end_time)

				elem_rules.append(elem_action)
				elem_action.append(elem_action_type)
				elem_action_type.append(elem_ingress_action)
				elem_ingress_action.append(elem_ingress_action_type)
				if 'Block' in policy_action :
					elem_ingress_action_type.append(elem_reject)
				else :
					elem_ingress_action_type.append(elem_pass)




			#======================XML part_3========================


				elem_under_rpc = Element("rpc")
				elem_under_rpc.attrib["xmlns"]="urn:ietf:params:xml:ns:netconf:base:1.0" 
				elem_under_rpc.attrib["message-id"]="2"
				temp_elem_under_rpc = Element("")
				temp_elem_under_rpc.text = "<close-session/>"
				temp_elem_under_rpc = ET.fromstring(temp_elem_under_rpc.text)
			#	elem_under_rpc = ET.fromstring(elem_under_rpc.text)
				elem_under_rpc.append(temp_elem_under_rpc)
			#======================XML def========================
				def indent(elem, level=0):
					i = "\n" + level*" "
					if len(elem):
						if not elem.text or not elem.text.strip():
							elem.text = i + ""
						if not elem.tail or not elem.text.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+1)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+2)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
					else:
						if level and (not elem.tail or not elem.tail.strip()):
							elem.tail = i

				f_write = open("./policy/firewall.xml", 'w')	
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(hello)
				dump(hello)
				ElementTree(hello).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")	
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(rpc)
				dump(rpc)
				ElementTree(rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				indent(elem_under_rpc)
				dump(elem_under_rpc)
				f_write.write(data)
				ElementTree(elem_under_rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				data = "]]>]]>"
				f_write.write(data)


				f_write.close()

				os.system("rm test.xml")
				os.system("sudo ../../../../confd-6.2/bin/netconf-console --host 10.0.0.200 policy/firewall.xml >> /tmp/webserver.out" )

			elif 'dpi_default_blacklist' in index:

				policy_id = "0"
				policy_name = "DPI_Default_Blacklist"
				policy_action = "Block"

				policy_sip_uri = []	


			#======================DB Part========================
				str_exe_position = "select * from Blacklist where SIP_URI;"

				db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Blacklist")
				cur = db.cursor()
				#if root[0][2].text == 'staff': 
				cur.execute(str_exe_position)
				for row in cur.fetchall():
					policy_sip_uri.append(row[1])
			#       		print row[0]
				policy_sip_uri_len = len(policy_sip_uri)
				db.close()

				print(policy_sip_uri)



			#======================XML Part_1========================

				hello = Element("hello")
				hello.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0"
				to = Element("capabilities")
				
				capabilities = Element("capability")
				to.text = " " 
				
				capabilities.text = "urn:ietf:params:netconf:base:1.0"
				hello.append(to)	
				to.append(capabilities)
				
			#======================XML Part_2========================
				temp_elem_target = Element("")
				temp_elem_target.text = "<running/>"
				temp_elem_target = ET.fromstring(temp_elem_target.text)


				rpc = Element("rpc")
				rpc.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0" 
				rpc.attrib["message-id"] = "1"

				elem_edit_config = Element("edit-config")
				rpc.append(elem_edit_config)

				elem_target = Element("target")
				elem_edit_config.append(elem_target)
				elem_edit_config.text = " "
				elem_target.append(temp_elem_target)
				elem_config = Element("config")
				elem_config.text = " "
				elem_edit_config.append(elem_config)

				elem_policy = Element("policy")
				elem_policy.attrib["xmlns"]="http://skku.com/iot/example/ietf-i2nsf-capability-interface" 
				elem_policy.attrib["xmlns:nc"]="urn:ietf:params:xml:ns:netconf:base:1.0"
				elem_config.append(elem_policy)
				
				elem_rules = Element("voip-volte-rule")
				elem_rules.attrib["nc:operation"]="create"
				elem_policy.append(elem_rules)

				elem_rule_name = Element("rule-name")
				elem_rule_name.text = '%s' % (policy_name)
				elem_rule_id = Element("rule-id")
				elem_rule_id.text = '%s' % (policy_id) 
				elem_event = Element("event")
				elem_rules.append(elem_rule_name)
				elem_rules.append(elem_rule_id)
				elem_rules.append(elem_event)

				elem_event_called_voip = Element("called-voip")
				elem_event_called_voip.text = "true" 
				elem_event.append(elem_event_called_voip)

				elem_condition = Element("condition")
				elem_condition.text = " "
				elem_rules.append(elem_condition)

				elem_sip_uri = []
				for i in range(policy_sip_uri_len):
					elem_sip_uri.append(Element("sip-uri"))
				for i in range(policy_sip_uri_len):
					elem_sip_uri[i].text = '%s' % (policy_sip_uri[i])
					elem_condition.append(elem_sip_uri[i])
				
				elem_action = Element("action")
				elem_action.text = " "
				elem_rules.append(elem_action)

				elem_action_type = Element("action-type")
				elem_action_type.text = " "
				elem_action.append(elem_action_type)

				elem_ingress_action = Element("ingress-action")
				elem_ingress_action.text = " "
				elem_action_type.append(elem_ingress_action)

				elem_pass = Element("pass")
				elem_reject = Element("reject")
				if 'Block' in policy_action :
					elem_reject.text = "true"
				else :
					elem_pass.text = "true"

				if 'Block' in policy_action :
					elem_ingress_action.append(elem_reject)
				else :
					elem_ingress_action.append(elem_pass)

			#======================XML part_3========================


				elem_under_rpc = Element("rpc")
				elem_under_rpc.attrib["xmlns"]="urn:ietf:params:xml:ns:netconf:base:1.0" 
				elem_under_rpc.attrib["message-id"]="2"
				temp_elem_under_rpc = Element("")
				temp_elem_under_rpc.text = "<close-session/>"
				temp_elem_under_rpc = ET.fromstring(temp_elem_under_rpc.text)
			#	elem_under_rpc = ET.fromstring(elem_under_rpc.text)
				elem_under_rpc.append(temp_elem_under_rpc)
			#======================XML def========================
				def indent(elem, level=0):
					i = "\n" + level*" "
					if len(elem):
						if not elem.text or not elem.text.strip():
							elem.text = i + ""
						if not elem.tail or not elem.text.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+1)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+2)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
					else:
						if level and (not elem.tail or not elem.tail.strip()):
							elem.tail = i

				f_write = open("./policy/dpi_default_blacklist.xml", 'w')	
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(hello)
				dump(hello)
				ElementTree(hello).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")	
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(rpc)
				dump(rpc)
				ElementTree(rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				indent(elem_under_rpc)
				dump(elem_under_rpc)
				f_write.write(data)
				ElementTree(elem_under_rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				data = "]]>]]>"
				f_write.write(data)


				f_write.close()

				os.system("rm test.xml")
				os.system("sudo ../../../../confd-6.2/bin/netconf-console --host 10.0.0.102 policy/dpi_default_blacklist.xml >> /tmp/webserver.out" )

			elif 'dpi_blacklist' in index:
				print type(data)
				root = ET.fromstring(data)

				policy_id = root[0][0].text
				policy_name = root[0][1].text
				policy_sip_uri = root[0][2].text
				policy_action = root[0][3].text

				print(policy_id)
				print(policy_name)
				print(policy_sip_uri)
				print(policy_action)
		#		print(policy_action)

			#======================XML Part_1========================

				hello = Element("hello")
				hello.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0"
				to = Element("capabilities")
				
				capabilities = Element("capability")
				to.text = " " 
				
				capabilities.text = "urn:ietf:params:netconf:base:1.0"
				hello.append(to)	
				to.append(capabilities)
				
			#======================XML Part_2========================
				temp_elem_target = Element("")
				temp_elem_target.text = "<running/>"
				temp_elem_target = ET.fromstring(temp_elem_target.text)


				rpc = Element("rpc")
				rpc.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0" 
				rpc.attrib["message-id"] = "1"

				elem_edit_config = Element("edit-config")
				rpc.append(elem_edit_config)

				elem_target = Element("target")
				elem_edit_config.append(elem_target)
				elem_edit_config.text = " "
				elem_target.append(temp_elem_target)
				elem_config = Element("config")
				elem_config.text = " "
				elem_edit_config.append(elem_config)

				elem_policy = Element("policy")
				elem_policy.attrib["xmlns"]="http://skku.com/iot/example/ietf-i2nsf-capability-interface" 
				elem_policy.attrib["xmlns:nc"]="urn:ietf:params:xml:ns:netconf:base:1.0"
				elem_config.append(elem_policy)
				
				elem_rules = Element("voip-volte-rule")
				elem_rules.attrib["nc:operation"]="create"
				elem_policy.append(elem_rules)

				elem_rule_name = Element("rule-name")
				elem_rule_name.text = '%s' % (policy_name)
				elem_rule_id = Element("rule-id")
				elem_rule_id.text = '%s' % (policy_id) 
				elem_event = Element("event")
				elem_rules.append(elem_rule_name)
				elem_rules.append(elem_rule_id)
				elem_rules.append(elem_event)

				elem_event_called_voip = Element("called-voip")
				elem_event_called_voip.text = "true" 
				elem_event.append(elem_event_called_voip)

				elem_condition = Element("condition")
				elem_condition.text = " "
				elem_rules.append(elem_condition)

				elem_sip_uri = Element("sip-uri")
				elem_sip_uri.text = '%s' % (policy_sip_uri)
				elem_condition.append(elem_sip_uri)

				elem_action = Element("action")
				elem_action.text = " "
				elem_rules.append(elem_action)

				elem_action_type = Element("action-type")
				elem_action_type.text = " "
				elem_action.append(elem_action_type)

				elem_ingress_action = Element("ingress-action")
				elem_ingress_action.text = " "
				elem_action_type.append(elem_ingress_action)

				elem_pass = Element("pass")
				elem_reject = Element("reject")
				if 'Block' in policy_action :
					elem_reject.text = "true"
				else :
					elem_pass.text = "true"

				if 'Block' in policy_action :
					elem_ingress_action.append(elem_reject)
				else :
					elem_ingress_action.append(elem_pass)

			#======================XML part_3========================


				elem_under_rpc = Element("rpc")
				elem_under_rpc.attrib["xmlns"]="urn:ietf:params:xml:ns:netconf:base:1.0" 
				elem_under_rpc.attrib["message-id"]="2"
				temp_elem_under_rpc = Element("")
				temp_elem_under_rpc.text = "<close-session/>"
				temp_elem_under_rpc = ET.fromstring(temp_elem_under_rpc.text)
			#	elem_under_rpc = ET.fromstring(elem_under_rpc.text)
				elem_under_rpc.append(temp_elem_under_rpc)
			#======================XML def========================
				def indent(elem, level=0):
					i = "\n" + level*" "
					if len(elem):
						if not elem.text or not elem.text.strip():
							elem.text = i + ""
						if not elem.tail or not elem.text.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+1)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+2)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
					else:
						if level and (not elem.tail or not elem.tail.strip()):
							elem.tail = i

				f_write = open("./policy/dpi_blacklist.xml", 'w')	
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(hello)
				dump(hello)
				ElementTree(hello).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")	
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(rpc)
				dump(rpc)
				ElementTree(rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				indent(elem_under_rpc)
				dump(elem_under_rpc)
				f_write.write(data)
				ElementTree(elem_under_rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				data = "]]>]]>"
				f_write.write(data)


				f_write.close()

				os.system("rm test.xml")
				os.system("sudo ../../../../confd-6.2/bin/netconf-console --host 10.0.0.102 policy/dpi_blacklist.xml >> /tmp/webserver.out" )


			elif 'dpi_user_agent' in index:
				print type(data)
				root = ET.fromstring(data)
				policy_user_agent = []
				
				if len(root[0]) == 4:
					policy_id = root[0][0].text
					policy_name = root[0][1].text
					policy_user_agent.append(root[0][2].text)
					policy_action = root[0][3].text
					policy_user_agent_len = 1;
					print(policy_id)
					print(policy_name)
					print(policy_user_agent)
					print(policy_action)
				elif len(root[0]) == 5:
					policy_id = root[0][0].text
					policy_name = root[0][1].text
					policy_user_agent.append(root[0][2].text)
					policy_user_agent.append(root[0][3].text)
					policy_action = root[0][4].text
					policy_user_agent_len = 2;
					print(policy_id)
					print(policy_name)
					print(policy_user_agent)
					print(policy_action)
				elif len(root[0]) == 6:
					policy_id = root[0][0].text
					policy_name = root[0][1].text
					policy_user_agent.append(root[0][2].text)
					policy_user_agent.append(root[0][3].text)
					policy_user_agent.append(root[0][4].text)
					policy_action = root[0][5].text
					policy_user_agent_len = 3;
					print(policy_id)
					print(policy_name)
					print(policy_user_agent)
					print(policy_action)

			#======================XML Part_1========================

				hello = Element("hello")
				hello.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0"
				to = Element("capabilities")
				
				capabilities = Element("capability")
				to.text = " " 
				
				capabilities.text = "urn:ietf:params:netconf:base:1.0"
				hello.append(to)	
				to.append(capabilities)
				
			#======================XML Part_2========================
				temp_elem_target = Element("")
				temp_elem_target.text = "<running/>"
				temp_elem_target = ET.fromstring(temp_elem_target.text)


				rpc = Element("rpc")
				rpc.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0" 
				rpc.attrib["message-id"] = "1"

				elem_edit_config = Element("edit-config")
				rpc.append(elem_edit_config)

				elem_target = Element("target")
				elem_edit_config.append(elem_target)
				elem_edit_config.text = " "
				elem_target.append(temp_elem_target)
				elem_config = Element("config")
				elem_config.text = " "
				elem_edit_config.append(elem_config)

				elem_policy = Element("policy")
				elem_policy.attrib["xmlns"]="http://skku.com/iot/example/ietf-i2nsf-capability-interface" 
				elem_policy.attrib["xmlns:nc"]="urn:ietf:params:xml:ns:netconf:base:1.0"
				elem_config.append(elem_policy)
				
				elem_rules = Element("voip-volte-rule")
				elem_rules.attrib["nc:operation"]="create"
				elem_policy.append(elem_rules)

				elem_rule_name = Element("rule-name")
				elem_rule_name.text = '%s' % (policy_name)
				elem_rule_id = Element("rule-id")
				elem_rule_id.text = '%s' % (policy_id) 
				elem_event = Element("event")
				elem_rules.append(elem_rule_name)
				elem_rules.append(elem_rule_id)
				elem_rules.append(elem_event)

				elem_event_called_voip = Element("called-voip")
				elem_event_called_voip.text = "true" 
				elem_event.append(elem_event_called_voip)

				elem_condition = Element("condition")
				elem_condition.text = " "
				elem_rules.append(elem_condition)

				elem_sip_user_agent = []
				for i in range(policy_user_agent_len):
					elem_sip_user_agent.append(Element("sip-user-agent"))
				for i in range(policy_user_agent_len):
					elem_sip_user_agent[i].text = '%s' % (policy_user_agent[i])
					elem_condition.append(elem_sip_user_agent[i])

				elem_action = Element("action")
				elem_action.text = " "
				elem_rules.append(elem_action)

				elem_action_type = Element("action-type")
				elem_action_type.text = " "
				elem_action.append(elem_action_type)

				elem_ingress_action = Element("ingress-action")
				elem_ingress_action.text = " "
				elem_action_type.append(elem_ingress_action)

				elem_pass = Element("pass")
				elem_reject = Element("reject")
				if 'Block' in policy_action :
					elem_reject.text = "true"
				else :
					elem_pass.text = "true"

				if 'Block' in policy_action :
					elem_ingress_action.append(elem_reject)
				else :
					elem_ingress_action.append(elem_pass)

			#======================XML part_3========================


				elem_under_rpc = Element("rpc")
				elem_under_rpc.attrib["xmlns"]="urn:ietf:params:xml:ns:netconf:base:1.0" 
				elem_under_rpc.attrib["message-id"]="2"
				temp_elem_under_rpc = Element("")
				temp_elem_under_rpc.text = "<close-session/>"
				temp_elem_under_rpc = ET.fromstring(temp_elem_under_rpc.text)
			#	elem_under_rpc = ET.fromstring(elem_under_rpc.text)
				elem_under_rpc.append(temp_elem_under_rpc)
			#======================XML def========================
				def indent(elem, level=0):
					i = "\n" + level*" "
					if len(elem):
						if not elem.text or not elem.text.strip():
							elem.text = i + ""
						if not elem.tail or not elem.text.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+1)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
						for elem in elem:
							indent(elem, level+2)
						if not elem.tail or not elem.tail.strip():
							elem.tail = i
					else:
						if level and (not elem.tail or not elem.tail.strip()):
							elem.tail = i

				f_write = open("./policy/dpi_user_agent.xml", 'w')	
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(hello)
				dump(hello)
				ElementTree(hello).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")	
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				f_write.write(data)
				indent(rpc)
				dump(rpc)
				ElementTree(rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
				data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				indent(elem_under_rpc)
				dump(elem_under_rpc)
				f_write.write(data)
				ElementTree(elem_under_rpc).write("test.xml")

				f_read = open("test.xml", 'r')
				while True:
					line = f_read.readline()
					if not line: break
					f_write.write(line)
				f_read.close()

				print("]]>]]>")
				data = "]]>]]>"
				f_write.write(data)


				f_write.close()

				os.system("rm test.xml")
				os.system("sudo ../../../../confd-6.2/bin/netconf-console --host 10.0.0.102 policy/dpi_user_agent.xml >> /tmp/webserver.out" )

			self.send_response(200);
			self.send_header("Content-type", "text/json");
			self.end_headers();
			self.wfile.write(json.dumps({'code': response_code, 'message': response_msg}));
			if response_code == 200:
				parse_to_yang(nsf_name, policy_name, rule);

if __name__ == '__main__':
	server_class = BaseHTTPServer.HTTPServer
	httpd = server_class((HOST_NAME, PORT_NUMBER), RequestHandler)
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()



		#------------------------------------------------------ #
		# TCP_IP = '127.0.0.1'
		# TCP_PORT = 6000
		# BUFFER_SIZE = 4096  # Normally 1024, but we want fast response
		 
		# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# s.bind((TCP_IP, TCP_PORT))
		# s.listen(1)
		# #os.system("les >> /tmp/test.txt")


		# while True:
		# 	print("Now listening...\n")
		# 	conn, addr = s.accept()

		# 	print 'New connection from %s:%d' % (addr[0], addr[1])

		# 	index = conn.recv(BUFFER_SIZE)
		# 	data = conn.recv(BUFFER_SIZE)

		# 	print data
		# #	index = data.split(',')[0]
		# #	data = data.split(',')[1]

		# 	print index
		# 	print data
			
		#    print type(data)
			
