#~/bin/sh

if [ "$#" -lt 2 ]; then
    echo "Usage: ./sendFlowScript.sh [PUT or DELETE] [IP Address with port of controller]"
    exit 1
fi

###################### ALL PROTOCOL ##################################
# Staff_1 -> Switch_2
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:4/table/0/flow/Test01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>Test01</flow-name><id>Test01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:4:5</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><in-port>openflow:4:1</in-port></match></flow>'



# Switch_2 -> SFF
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/Test02" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>Test02</flow-name><id>Test02</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:2:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><in-port>openflow:2:4</in-port></match></flow>'

# SFF -> Switch_1
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/Test11" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>Test11</flow-name><id>Test11</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:2:2</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><in-port>openflow:2:1</in-port></match></flow>'


# Switch_1 -> Firewall
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/Test04" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>Test04</flow-name><id>Test04</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><in-port>openflow:1:4</in-port></match></flow>'

# Firewall -> Switch3
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/Test05" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>Test05</flow-name><id>Test05</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:5</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><in-port>openflow:1:1</in-port></match></flow>'

# Switch_3 -> Internet
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/Test06" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>Test06</flow-name><id>Test06</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:5</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><in-port>openflow:3:8</in-port></match></flow>'





###################### IP ##################################

# Switch_2 -> SFF
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/IP01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>IP01</flow-name><id>IP01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:2:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><in-port>openflow:2:4</in-port></match></flow>'

# SFF -> Switch_1
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/IP02" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>IP02</flow-name><id>IP02</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:2:2</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><in-port>openflow:2:1</in-port></match></flow>'


# Switch_1 -> Firewall
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/IP01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>IP01</flow-name><id>IP01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><in-port>openflow:1:4</in-port></match></flow>'

# Firewall -> Switch3
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/IP02" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>IP02</flow-name><id>IP02</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:5</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><in-port>openflow:1:1</in-port></match></flow>'

# Switch_3 -> Internet
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/IP01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>IP01</flow-name><id>IP01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>1</ip-protocol></ip-match><in-port>openflow:3:3</in-port></match></flow>'

######################TCP##################################

# Switch_2 -> SFF
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/TCP01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>TCP01</flow-name><id>TCP01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:2:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>6</ip-protocol></ip-match><in-port>openflow:2:4</in-port></match></flow>'

# SFF -> Switch_1
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:2/table/0/flow/TCP02" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>TCP02</flow-name><id>TCP02</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:2:2</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>6</ip-protocol></ip-match><in-port>openflow:2:1</in-port></match></flow>'


# Switch_1 -> Firewall
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/TCP01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>TCP01</flow-name><id>TCP01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>6</ip-protocol></ip-match><in-port>openflow:1:4</in-port></match></flow>'

# Firewall -> Switch3
#curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/TCP02" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>TCP02</flow-name><id>TCP02</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:1:5</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>6</ip-protocol></ip-match><in-port>openflow:1:1</in-port></match></flow>'

# Switch_3 -> Internet
curl -X "$1" -H "Content-Type: application/xml" "http://$2/restconf/config/opendaylight-inventory:nodes/node/openflow:3/table/0/flow/TCP01" -v -u admin:admin -d '<?xml version="1.0" encoding="UTF-8" standalone="no"?><flow xmlns="urn:opendaylight:flow:inventory"><strict>false</strict><flow-name>TCP01</flow-name><id>TCP01</id><cookie_mask>255</cookie_mask><cookie>103</cookie><table_id>0</table_id><priority>100</priority><hard-timeout>1200</hard-timeout><idle-timeout>3400</idle-timeout><installHw>false</installHw><instructions><instruction><order>0</order><apply-actions><action><order>0</order><output-action><output-node-connector>openflow:3:1</output-node-connector><max-length>65535</max-length></output-action></action></apply-actions></instruction></instructions><match><ethernet-match><ethernet-type><type>2048</type></ethernet-type></ethernet-match><ip-match><ip-protocol>6</ip-protocol></ip-match><in-port>openflow:3:3</in-port></match></flow>'
