<?php
function array_to_xml( $data, &$xml_data ) {
    foreach( $data as $key => $value ) {
        if( is_array($value) ) {
            if( is_numeric($key) ){
                $key = 'Policy_web';
            }
            $subnode = $xml_data->addChild($key);
            array_to_xml($value, $subnode);
        } else {
            $xml_data->addChild($key, htmlspecialchars($value));
        }
    }
}

$servername="localhost";
$username="root";
$password="secu";
$conn=mysql_connect(localhost, $username, $password) or die ("Error connecting to mysql server: ".mysql_error());
            
$dbname = 'I2NSF';
mysql_select_db($dbname, $conn) or die ("Error selecting specified database on mysql server: ".mysql_error());

$Web = $_GET["web_mode"];
$Rule_name = $_GET["Mode"];

$arr = explode(":", $Web, 3);
$Rule_id = $arr[1];
$arr = explode("Rule_name", $Rule_id, 2);
$Rule_id = $arr[0];
$Rule_id = str_replace(' ','', $Rule_id);


$result = mysql_query("SELECT * FROM Policy_web WHERE Rule_id=$Rule_id");

$rows = array();
while($r = mysql_fetch_assoc($result)){

$rows[] = $r;
}
$jsond = json_encode($rows, true);

// Creating an XML File //
$data = $jsond;
 
$xml_data = new SimpleXMLElement('<?xml version="1.0"?><I2NSF></I2NSF>');
array_to_xml(json_decode($data, true), $xml_data);
$result = $xml_data -> asXML();
 
header('Content-Type: text/xml; charset=UTF-8');
print_r($result);

$host = "127.0.0.1";
$TCP_PORT = 6000;
$output= "web,delete,".$result;
$socket = socket_create(AF_INET, SOCK_STREAM,0);
socket_connect ($socket , $host,$TCP_PORT );
socket_write($socket, $output, strlen ($output));
socket_close($socket);


//$url="http://192.168.115.130:8000/restconf/config/sc/nsf/firewall/policy/testPolicy/".$jsond;
//header('Location:'.$url);

//echo $jsond;
sleep(1);
$updatesql="DELETE FROM Policy_web WHERE Rule_id='$Rule_id';";
mysql_query($updatesql) or die("Query to delete record in Policy_enterprise failed with this error: ".mysql_error());

mysql_close($conn);


header( "refresh:1;url=select_page.php" );

?>


