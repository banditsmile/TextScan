<?php

class TextScan
{
    private $accessKey = '';
    private $accessSecret = '';
    private $baseUrl = 'https://green.cn-shenzhen.aliyuncs.com';
    private $signDate;
    public function __construct()
    {
        $this->signDate = gmdate ('D, d M Y H:i:s \G\M\T');
    }

    public function scan($text)
    {
        $apiUrl = '/green/text/scan';
        $requestUrl = $this->baseUrl.$apiUrl;
        // 请求签名
        $signature = $this->getSignature($this->accessSecret, $apiUrl, $this->signDate);
        $requestData = $this->requestData($text);
        $header = $this->getHeader($this->accessKey, $signature, $this->signDate);
        return $this->queryRequest($requestUrl, $requestData, $header);
    }

    /**
     * @param string $text 待审核文本
     * @return int 审核结果-1审核不通过,0待人工审查1审核通过
     */
    public function check(string $text)
    {
        if(empty($text)){
            return 1;
        }
        if(!$this->selfCheck($text)){
            return -1;
        }
        
        $data = $this->scan($text);

        //文本检测功能本身出现了异常，直接放行
        if($data['code']!=200){
            return 1;
        }
        $status = 1;
        foreach($data['data'] as $item){
            foreach($item['results'] as $result){
                if($result['suggestion']=='block'){
                    return -1;
                }
                //有需要人工审核的内容
                if($result['suggestion']=='review'){
                    $status=0;
                }
            }
        }

        return $status;
    }

    private function selfCheck($text)
    {
        $words=['毒品'];
        foreach($words as $word){
            if(strpos($text, $word)!==false){
                return false;
            }
        }
        return true;
    }

    /**
     * 请求header头
     *
     * @param $accessKey
     * @param $signature
     * @param $signDate
     * @return array
     */
    private function getHeader($accessKey, $signature, $signDate)
    {
        return [
            'x-sdk-client' => 'php/2.0.0',
            'x-acs-version' => '2018-05-09',
            'Date' => $signDate,
            'Accept' => 'application/json',
            'x-acs-signature-method' => 'HMAC-SHA1',
            'x-acs-signature-version' => '1.0',
            'x-acs-region-id' => 'cn-shanghai',
            'Content-Type' => 'application/json;charset=utf-8',
            'Authorization' => 'acs'.' '.$accessKey.':'.$signature,
        ];
    }

    /**
     * 请求参数
     *
     * @param $str
     * @return false|string
     */
    private function requestData($str)
    {
        $arr = json_encode([
            "tasks" => [
                [
                    'dataId' =>  uniqid(),
                    'content' => $str
                ]
            ],
            "scenes" => ["antispam"]
        ]);

        return $arr;
    }

    /**
     * 生成签名
     * @param $accessSecret
     * @param $apiUrl
     * @param $signDate
     * @return string
     */
    private function getSignature($accessSecret, $apiUrl, $signDate)
    {
        $source = "POST\n";
        $source .= "application/json\n";
        $source .= "\n";
        $source .= "application/json;charset=utf-8\n";
        $source .= $signDate."\n";
        $source .= "x-acs-region-id:cn-shanghai\n";
        $source .= "x-acs-signature-method:HMAC-SHA1\n";
        $source .= "x-acs-signature-version:1.0\n";
        $source .= "x-acs-version:2018-05-09\n";
        $source .= $apiUrl;
        return base64_encode(hash_hmac('sha1', $source, $accessSecret, true));

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
        $response = $client->request('POST', $requestUrl,$option);
        $result = ['code'=>$response->getStatusCode(),'msg'=>'网络请求失败', 'data'=>''];
        if($result['code']!=200){
            return $result;
        }
        $body=$response->getBody();
        $content = $body->getContents();
        $data = json_decode($content, true);
        if(!isset($data['code'])){
            $data['code']=1;
            $data['msg']='返回数据格式异常';
            return $result;
        }
        return $data;
    }
}
