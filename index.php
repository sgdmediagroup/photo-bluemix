<?
// Generated by curl-to-PHP: http://incarnate.github.io/curl-to-php/
$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, 'https://iam.cloud.ibm.com/identity/token?apikey=vSYzfvzLh5SkHyn80U6Za_u0u1EL4CTQyV4dOFBY5FeX&grant_type=urn:ibm:params:oauth:grant-type:apikey');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);

$headers = array();
$headers[] = 'Content-Type: application/x-www-form-urlencoded';
$headers[] = 'Accept: application/json';
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

$result = curl_exec($ch);
if (curl_errno($ch)) {
    echo 'Error:' . curl_error($ch);
}
curl_close ($ch);

$result = json_decode($result);

var_dump($result);

echo "<br>";

echo "<br>";




// Generated by curl-to-PHP: http://incarnate.github.io/curl-to-php/
$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, 's3.us.cloud-object-storage.appdomain.cloud');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');


$headers = array();
$headers[] = 'Authorization: '.$result->access_token.'';
$headers[] = 'ibm-service-instance-id: 0ec4a03c-17da-4f55-945d-1ca7646564c9';
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

$result = curl_exec($ch);
if (curl_errno($ch)) {
    echo 'Error:' . curl_error($ch);
}
echo($result);
curl_close ($ch);
