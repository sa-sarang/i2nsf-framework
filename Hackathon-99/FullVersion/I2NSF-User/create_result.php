<?php
function array_to_xml( $data, &$xml_data ) {
    foreach( $data as $key => $value ) {
        if( is_array($value) ) {
            if( is_numeric($key) ){
                $key = 'Policy_enterprise';
            }
            $subnode = $xml_data->addChild($key);
            array_to_xml($value, $subnode);
        } else {
            $xml_data->addChild($key, htmlspecialchars($value));
        }
    }
}

$servername = "localhost";
$username = "root";
$password = "secu";
$conn=mysql_connect(localhost, $username, $password) or die ("Error connecting to mysql server: ".mysql_error());
$dbname = 'I2NSF';
mysql_select_db($dbname, $conn) or die ("Error selecting specified database on mysql server: ".mysql_error());

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (empty($_POST["Rule_name"])) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Please fill in all required fields.</span><br><br>');

    header( "refresh:3;url=rule_create.php" );
    return false;

  }else{

if (strlen($_POST["Rule_name"]) < 3) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Policy name must be at least 3 characters long.</span><br><br>');
    header( "refresh:3;url=rule_create.php" );

    return false;

  } else {
    if (strlen($_POST["Rule_name"]) > 32) {
    echo nl2br('<span style="color:#FF0000;text-align:center;">Policy name should be no longer than 32 characters.</span><br><br>');
    header( "refresh:3;url=rule_create.php" );

    return false;

    }
  
}

}
  
}
$Rule_name = $_POST["Rule_name"];


$createsql = "INSERT INTO Policy_enterprise (Rule_name) VALUES ('$Rule_name')";
mysql_query($createsql) or die("Query to create record in Policy_enterprise failed with this error: ".mysql_error()); 


$result = mysql_query("SELECT * FROM Policy_enterprise ORDER BY Rule_id DESC LIMIT 1");

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


mysqli_close($conn);

//$url="http://192.168.115.130:8000/restconf/config/sc/nsf/firewall/policy/testPolicy/".$jsond;
//header('Location:'.$url);

//Connect to a local server //
$host = "127.0.0.1";
$TCP_PORT = 6000;
$output= "enterprise-mode,create,".$result;
$socket = socket_create(AF_INET, SOCK_STREAM,0);
socket_connect ($socket , $host,$TCP_PORT );
socket_write($socket, $output, strlen ($output));
socket_close($socket);

header( "refresh:3;url=select_page.php" );
// Creating a text log file //

//$date = date_create("NOW");
//$file = 'log.txt';
//$test = date_format($date,"Y/m/d H:i:s") . '-' . $_POST["Rule_name"] . '-' . $_POST["Position"] . '-' . $_POST["Website"] . '-' . $_POST["Starting_Time"] . '-' . $_POST["Ending_Time"] . '-' . $_POST["Action"] . "\n";
//$ret = file_put_contents($file, $test, FILE_APPEND | LOCK_EX);


//header("refresh:0;url=qfc2.php/api/Policy_web");

/*
$url = "http://localhost/policy.txt";


$postvars='';

$sep='';

foreach($data as $key=>$value)
{
        $postvars.= $sep.urlencode($key).'='.urlencode($value);
        $sep='&';
}

echo $postvars;

$ch = curl_init();

curl_setopt($ch,CURLOPT_URL,$url);
curl_setopt($ch,CURLOPT_POST,count($data));
curl_setopt($ch,CURLOPT_POSTFIELDS,$postvars);
curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);

$result = curl_exec($ch);

curl_close($ch);

echo $result;

*/



?>
