<?php


class TextScan
{
    //在这里输入secretId
    private $secretId = '';
    //在这里输入secretKey
    private $secretKey = '';
    private $host = "tms.tencentcloudapi.com";
    private $service = "tms";
    private $version = "2020-12-29";
    private $action = "TextModeration";
    private $region = "ap-guangzhou";
    private $algorithm = "TC3-HMAC-SHA256";

    // step 1: build canonical request string
    private $requestMethod = "POST";
    private $canonicalUri = "/";
    private $date;
    private $timestamp;
    public function __construct()
    {
        $this->timestamp = time();
        $this->date = gmdate("Y-m-d", $this->timestamp);
    }

    public function scan($text)
    {
        $requestUrl = 'https://'.$this->host;
        $payload = $this->requestData($text);
        $signature = $this->getSignature($payload);
        $header = $this->getHeader($signature);
        return $this->queryRequest($requestUrl, $payload, $header);
    }


    /**
     * 组织请求头
     *
     * @param $signature
     * @return array
     */
    private function getHeader($signature)
    {

        // step 4: build authorization
        $credentialScope = $this->date."/".$this->service."/tc3_request";
        $authorization = $this->algorithm
            ." Credential=".$this->secretId."/".$credentialScope
            .", SignedHeaders=content-type;host, Signature=".$signature;

        return [
            'Authorization'=>$authorization,
            'Content-Type'=>'application/json; charset=utf-8',
            'Host'=>$this->host,
            'X-TC-Action' =>   $this->action,
            'X-TC-Timestamp' =>   $this->timestamp,
            'X-TC-Version' =>   $this->version,
            'X-TC-Region' =>   $this->region,
        ];
    }

    /**
     * 请求参数
     *
     * @param $str
     * @return false|string
     */
    private function requestData($str,$dataId='',$device='', $userId='')
    {
        $data = [
            "Content" => base64_encode($str)
        ];
        $dataId && $data['DataId']=$dataId;
        $device && $data['Device']=['IP'=>'127.0.0.1'];
        $userId && $data['User'] = ['UserId'=>$userId];
        return $data;
    }


    /**
     * 生成签名
     *
     * @param $payload
     * @return string
     */
    private function getSignature($payload)
    {
        $payload = json_encode($payload);
        // step 1: build canonical request string
        $canonicalQueryString = "";
        $canonicalHeaders = "content-type:application/json; charset=utf-8\n"."host:".$this->host."\n";
        $signedHeaders = "content-type;host";
        $hashedRequestPayload = hash("SHA256", $payload);
        $canonicalRequest = $this->requestMethod."\n".
            $this->canonicalUri."\n".
            $canonicalQueryString."\n".
            $canonicalHeaders."\n".
            $signedHeaders."\n".
            $hashedRequestPayload;

        // step 2: build string to sign
        $credentialScope = $this->date."/".$this->service."/tc3_request";
        $hashedCanonicalRequest = hash("SHA256", $canonicalRequest);
        $stringToSign = $this->algorithm."\n".
            $this->timestamp."\n".
            $credentialScope."\n".
            $hashedCanonicalRequest;

        // step 3: sign string
        $secretDate = hash_hmac("SHA256", $this->date, "TC3".$this->secretKey, true);
        $secretService = hash_hmac("SHA256", $this->service, $secretDate, true);
        $secretSigning = hash_hmac("SHA256", "tc3_request", $secretService, true);
        return  hash_hmac("SHA256", $stringToSign, $secretSigning);
    }


    /**
     * 发送post请求
     *
     * @param $requestUrl
     * @param $requestData
     * @param $header
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    private function queryRequest($requestUrl, $requestData, $header)
    {
        $client = new \GuzzleHttp\Client();
        $option = [
            'json' => $requestData,
            'headers' => $header,
        ];
        $response = $client->request($this->requestMethod, $requestUrl,$option);
        $body=$response->getBody();
        $content = $body->getContents();
        return  json_decode($content, true);
    }
}





