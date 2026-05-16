<?php
/**
 * SiteGuarding tools installer for customer's panel
 *
 * https://www.siteguarding.com
 * Do not distribute or share.
 * 
 * ver.: 2.3
 * Date: 16 January 2026
 */
$allowed_IPs = array(
    '198.7.59.150',
    '198.7.59.167',
    '198.7.59.168',
);

define('VERSION', '2.3');

define('DEBUG_MODE', false);

define('SITEGUARDING_SERVER', 'http://www.siteguarding.com/ext/panel_api/index.php');

$private_pgp_key = '-----BEGIN PRIVATE KEY-----
MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEwggE9AgEAAkEApvw/ix3k2/D/yMlh
u9LhnpP6pna/91J+V4j0HeAiCmQu8wqnaQtXBUILUYk6jqu+KemuMNzocfA7rxEW
PWTCrQIDAQABAkEAhJu7prHlxlh7+KscZzlQHUvs+HdDeZhUZxWGr5cH0XF3eNoc
8tRF9kVoIwcAOcpM8s1ngkv83wQ9okD9tYxwjQIhANKzekmRpdp0dOxw+IctkWuG
h0hA5I5vUcbsM9Q86tzbAiEAyuLAtG17ucDJlj64eltAcyp2mSdS9xzG1h8zxSyf
MRcCIQCHtHUUoSwzMUKFbpWDawP4PyMulC0g1+3RsxwGnF2gdQIhAMkICf4+Bby3
JIg1OcIzrRbwWnfDGVg2MWd1n2yenFadAiEAzlDVVGN4Fn/0VM0pWD71hKw9TK3X
bS4xpkyQlDKC96c=
-----END PRIVATE KEY-----';


$scan_path = dirname(__FILE__);
if (!defined('DIRSEP'))
{
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') define('DIRSEP', '\\');
    else define('DIRSEP', '/');
}
define('WEBSITE_ROOT', dirname(__FILE__).DIRSEP);


// Init
date_default_timezone_set('Europe/London');
ignore_user_abort(true);
error_reporting( 0 );
ini_set('error_log', '');
ini_set('log_errors', 0);
ini_set('max_execution_time', 7200);
set_time_limit( 7200 );
ini_set('memory_limit', '1024M');


/**
 * Start
 */
$ip_address = isset($_SERVER["REMOTE_ADDR"]) ? $_SERVER["REMOTE_ADDR"] : '127.0.0.1';
if (isset($_SERVER["HTTP_X_REAL_IP"]) && $_SERVER["HTTP_X_REAL_IP"] !== '') $ip_address = $_SERVER["HTTP_X_REAL_IP"];
if (isset($_SERVER["HTTP_X_FORWARDED_FOR"]) && $_SERVER["HTTP_X_FORWARDED_FOR"] !== '') $ip_address = $_SERVER["HTTP_X_FORWARDED_FOR"];
if (isset($_SERVER["HTTP_CF_CONNECTING_IP"]) && $_SERVER["HTTP_CF_CONNECTING_IP"] !== '') $ip_address = $_SERVER["HTTP_CF_CONNECTING_IP"];

if (DEBUG_MODE) SaveLog('Start session for '.$ip_address);
$task_id = '';
if (isset($_REQUEST['task_id']) && $_REQUEST['task_id'] !== null) $task_id = trim($_REQUEST['task_id']);
if ($task_id == '' && isset($_POST['task_id']) && $_POST['task_id'] !== null) $task_id = trim($_POST['task_id']);
if ($task_id == '') die('siteguarding_tools.php is ok (ver. '.VERSION.')'.CheckError());

$remote_md5 = isset($_REQUEST['latest_md5']) && $_REQUEST['latest_md5'] !== null ? trim($_REQUEST['latest_md5']) : ''; 
$latest_ver = isset($_REQUEST['latest_ver']) && $_REQUEST['latest_ver'] !== null ? trim($_REQUEST['latest_ver']) : ''; 


/**
 * Actions without authorization
 */

// Recovery action
if ($task_id == 'recovery')
{
    if (basename(dirname(__FILE__)) == 'webanalyze')
    {
        $restored_file = dirname(dirname(__FILE__)).DIRSEP.'siteguarding_tools.php';
        if (copy(__FILE__, $restored_file)) die('RESTORED_OK');
        else die('RESTORED_FAILED');
    }
    else die('RESTORE_IGNORED');
}


// Check if request came from allowed IP address
$is_allowed_session = false;
foreach ($allowed_IPs as $ip)
{
    if ($ip_address == trim($ip))
    {
        $is_allowed_session = true;
        break;
    }
}

if (DEBUG_MODE) SaveLog('Session is '.var_export($is_allowed_session, true));

// Check by host
if ($is_allowed_session === false)
{
    $host = gethostbyaddr($ip_address);
    if ($host !== false && is_string($host) && stripos($host, "hosting") === false && substr($host, -16) == 'siteguarding.com') $is_allowed_session = true;
}

// Check by PGP
if ($is_allowed_session === false)
{
    // Check session with PGP way
    $task_pgp = '';
    if (isset($_REQUEST['task_pgp']) && $_REQUEST['task_pgp'] !== null) $task_pgp = trim($_REQUEST['task_pgp']);
    if ($task_pgp == '' && isset($_POST['task_pgp']) && $_POST['task_pgp'] !== null) $task_pgp = trim($_POST['task_pgp']);
    if ($task_pgp == '') die('task_pgp error');
    
    if (!extension_loaded('openssl')) die('openssl extension is not installed on the server for PHP '.phpversion());
    
    $decrypted = PGP_decrypt($task_pgp, $private_pgp_key);
    $task_pgp = ($decrypted !== false && $decrypted !== null) ? trim($decrypted) : '';
    if (DEBUG_MODE) SaveLog('$task_id='.$task_id.' , $task_pgp='.$task_pgp);
    if ($task_pgp != $task_id) die('task_pgp wrong value');
}


/**
 * Actions with authorization
 */

// Self update
if ( ($remote_md5 != '' && is_string($remote_md5) && strlen($remote_md5) == 32) || (is_numeric($latest_ver) && $latest_ver > VERSION) )
{
    $log_file = Get_LogFile();
    if (!file_exists($log_file) || (time() - filectime($log_file) > 24 * 60 * 60) )
    {
        $own_md5 = md5_file(__FILE__);
        if ($own_md5 != $remote_md5) 
        {
            // Do self update
            SaveLog('Self Update. Own [ver. '.VERSION.'] md5: '.$own_md5.', remote [ver. '.$latest_ver.'] md5: '.$remote_md5);
            ManualUpdate();
        }
    }
}

// Ping action
if ($task_id == 'ping')
{
    $a = array('status' => 'PING_OK', 'ver' => VERSION, 'local_path' => WEBSITE_ROOT, 'self_md5' => md5_file(__FILE__));
    $login = WEBSITE_ROOT.'webanalyze'.DIRSEP.'website-security-conf.php';
    if (file_exists($login))
    {
        $a['login'] = Read_File($login);
    }
    
    $backup_file = WEBSITE_ROOT.'webanalyze'.DIRSEP.'siteguarding_tools.php';
    if (!file_exists($backup_file) || filesize(__FILE__) > filesize($backup_file))
    {
        $folder_webanalyze = WEBSITE_ROOT.'webanalyze';
        if (!file_exists($folder_webanalyze)) @mkdir($folder_webanalyze, 0755, true);
        copy(__FILE__, $backup_file);
    }
    
    die(json_encode($a));
}

// Manual Update
if ($task_id == 'update')
{
    $json = array('local_path' => WEBSITE_ROOT, 'current_ver' => VERSION, 'self_md5' => md5_file(__FILE__), 'update_status' => '');

	if (ManualUpdate()) $json['update_status'] = 'UPDATED';
	else $json['update_status'] = 'UPDATE FAILED';
    
    die( json_encode($json) );   
}


// Connect to SiteGuarding.com server
$link = SITEGUARDING_SERVER.'?action=siteguarding_tools&task_id='.$task_id;
$task_json_raw = GetRemote_file_contents($link);
$task_json_raw = ($task_json_raw !== false && $task_json_raw !== null) ? trim($task_json_raw) : '';
if ($task_json_raw == '') die('Empty task_json');
$task_json = json_decode($task_json_raw, true);
if (!is_array($task_json) || $task_json === null) die('False decode task_json');

foreach ($task_json as $task_code => $task_data)
{
	if (DEBUG_MODE) SaveLog('task_code='.$task_code);
    switch ($task_code)
    {
        case 'savefile':
            Task_savefile($task_data);
            break;
            
        case 'showfile':
            Task_showfile($task_data);
            break;
            
        case 'deletefile':
            Task_deletefile($task_data);
            break;
            
        case 'copyfile':
            Task_copyfile($task_data);
            break;
            
        case 'download':
            Task_download($task_data);
            break;
            
        case 'includefile':
            Task_includefile($task_data);
            break;
            
        case 'fileinfo':
            Task_fileinfo($task_data);
            break;
    }
}

exit;





/**
 * functions
 */

function Task_deletefile($task_data)
{
    if (!is_array($task_data) || count($task_data) == 0) return;
    
    foreach ($task_data as $data_row)
    {
        if (!is_array($data_row) || !isset($data_row['file'])) continue;
        $filename = $data_row['file'];
        
        if (file_exists(WEBSITE_ROOT.$filename)) @unlink(WEBSITE_ROOT.$filename);
    }
}


function Task_copyfile($task_data)
{
    if (!is_array($task_data) || count($task_data) == 0) return;
    
    foreach ($task_data as $data_row)
    {
        if (!is_array($data_row) || !isset($data_row['file']) || !isset($data_row['file_to'])) continue;
        $filename = $data_row['file'];
        $filename_to = $data_row['file_to'];
        
        if (file_exists(WEBSITE_ROOT.$filename)) @copy(WEBSITE_ROOT.$filename, WEBSITE_ROOT.$filename_to);
    }
}


function Task_savefile($task_data)
{
    if (!is_array($task_data) || count($task_data) == 0) return;
    
    foreach ($task_data as $data_row)
    {
        if (!is_array($data_row) || !isset($data_row['file'])) continue;
        $filename = $data_row['file'];
        
        if ($filename == 'create_folder') 
        {
            if (!isset($data_row['content'])) continue;
            $folder = WEBSITE_ROOT.$data_row['content'];
            if (!file_exists($folder)) @mkdir($folder, 0755, true);
            continue;
        }
        
        if (!isset($data_row['content'])) continue;
        $content = base64_decode($data_row['content']);
        
        if ($content !== false) 
        {
            if (isset($data_row['skip']) && intval($data_row['skip']) == 1)
            {
                if (file_exists(WEBSITE_ROOT.$filename)) continue;
            }
            Save_File(WEBSITE_ROOT.$filename, $content);
        }
    }
}


function Task_showfile($task_data)
{
    $a = array();
    if (!is_array($task_data) || count($task_data) == 0) return;
    
    foreach ($task_data as $data_row)
    {
        if (!is_array($data_row) || !isset($data_row['file'])) continue;
        $filename = $data_row['file'];
        $full_path = WEBSITE_ROOT.$filename;
        
        if (!file_exists($full_path)) continue;
        
        if (isset($data_row['size']))
        {
            // Show by size
            $current_size = filesize($full_path);
            if ($current_size !== false && $current_size == $data_row['size']) continue;
        }
        
        $a[$filename] = base64_encode(Read_File($full_path));
    }
    
    if (count($a) > 0)
    {
        echo json_encode($a);
    }
}

function Task_download($task_data)
{
    if (!is_array($task_data) || !isset($task_data['file'])) die('ERROR');
    
    $file = WEBSITE_ROOT.trim($task_data['file']);
    
    if (!is_file($file)) die('ERROR');
    
    $content = '';
    $filesize = 0;
    
    if (isset($task_data['size']))
    {
        $size = intval($task_data['size']);
        if ($size >= 0) 
        {
            $filesize = $size;
            if ($size == 0) 
            {
                ob_start();
                readfile($file);
                $content = ob_get_clean();
                if ($content === false) $content = '';
            }
            else {
                $fp = fopen($file, "rb");
                if ($fp !== false) {
                    $content = fread($fp, $size);
                    if ($content === false) $content = '';
                    fclose($fp);
                }
            }
        }
        else {
            $filesize = abs($size);
            $fp = fopen($file, 'rb');
            if ($fp !== false) {
                fseek($fp, $size, SEEK_END);
                $content = fgets($fp, $filesize + 1);
                if ($content === false) $content = '';
                fclose($fp);
            }
        }
    }
    else {
        // Read entire file
        $filesize = filesize($file);
        if ($filesize === false) $filesize = 0;
        
        if ($filesize > 0) {
            $content = file_get_contents($file);
            if ($content === false) {
                $content = '';
                $filesize = 0;
            }
        }
    }
    
    if (isset($task_data['lines']))
    {
        $lines = intval($task_data['lines']);
        
        $lines_data = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        if ($lines_data !== false && is_array($lines_data))
        {
            if ($lines > 0) $content_arr = array_slice($lines_data, 0, $lines);
            else $content_arr = array_slice($lines_data, $lines);
            
            $content = implode("\n", $content_arr);
            $filesize = strlen($content);
        }
        else {
            $content = '';
            $filesize = 0;
        }
    }
    
    if (!isset($content) || $content === false) $content = '';
    
    header('Pragma: public');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Cache-Control: private', false);
    header('Content-Transfer-Encoding: binary');
    header('Content-Disposition: attachment; filename="'.basename($file).'";');
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . $filesize);
    
    if (ob_get_level() > 0) ob_clean();
    flush();
    echo $content;
    exit;
}


function Task_fileinfo($task_data)
{
    $a = array();
    if (!is_array($task_data) || count($task_data) == 0) return;
    
    foreach ($task_data as $data_row)
    {
        if (!is_array($data_row) || !isset($data_row['file'])) continue;
        $filename = $data_row['file'];
        $full_path = WEBSITE_ROOT.$filename;
        
        if (is_file($full_path)) 
        {
            $md5file = '';
            if (isset($data_row['md5']) && intval($data_row['md5']) == 1) {
                $md5_result = md5_file($full_path);
                $md5file = ($md5_result !== false) ? $md5_result : '';
            }
            
            $fsize = filesize($full_path);
            $ftime = filectime($full_path);
            
            $a[$filename] = array(
                'exists' => 1, 
                'size' => ($fsize !== false ? $fsize : 0), 
                'time' => ($ftime !== false ? $ftime : 0), 
                'md5' => $md5file
            );
        }
        else $a[$filename] = array('exists' => 0);
    }
    
    if (count($a) > 0)
    {
        echo json_encode($a);
    }
}



function Task_includefile($task_data)
{
    if (!is_array($task_data) || !isset($task_data['code'])) return;
    
	if (DEBUG_MODE) SaveLog('Task_infile start');
    $folder_webanalyze = WEBSITE_ROOT.'webanalyze';
    if (!file_exists($folder_webanalyze)) @mkdir($folder_webanalyze, 0755, true);
    $include_file = $folder_webanalyze.DIRSEP.'tools_include_'.rand(0, 1000).'_'.rand(0, 1000).'.tmpcode';
	if (DEBUG_MODE) SaveLog('file='.$include_file);
    Save_File($include_file, $task_data['code']);
    if (file_exists($include_file)) {
        include($include_file);
        @unlink($include_file);
    }
	if (DEBUG_MODE) SaveLog('Task_infile end');
}


function Save_File($file, $content)
{
    $fp = @fopen($file, 'w');
    if ($fp === false) return false;
    fwrite($fp, $content);
    fclose($fp);
    return true;
}

function Read_File($file)
{
    $contents = '';
    
    if (!file_exists($file)) return $contents;
    
    $filesize = filesize($file);
    
    if ($filesize === false || $filesize == 0) return '';  // empty file or error
    
    $fp = @fopen($file, "rb");
    if ($fp === false) return $contents;
    
    if ($filesize < 512000)
    {
        $contents = fread($fp, $filesize);
        if ($contents === false) $contents = '';
    }
    else {
        while (!feof($fp)) {
            $chunk = fread($fp, 8192);
            if ($chunk === false) break;
            $contents .= $chunk;
        }
    }
    fclose($fp);
    
    return $contents;
}


function PGP_decrypt($data, $key)
{
    if (!is_string($data) || $data === '') return false;
    
	$data = base64_decode($data, false);
	if ($data === false) return false;
	
	$result = null;
	$status = openssl_private_decrypt($data, $result, $key);
    if (DEBUG_MODE) SaveLog('PGP decrypt status: '.var_export($status, true));
    if ($status === false) return false;
    return $result;
}



function ManualUpdate()
{
    $link = SITEGUARDING_SERVER.'?action=update';
    $response = GetRemote_file_contents($link);
    if ($response === false || $response === null || $response === '') return false;
    
    $response = is_string($response) ? trim($response) : '';
    if ($response === '') return false;
    
    $data = json_decode($response, true);
    if (!is_array($data) || !isset($data['b64content']) || !isset($data['md5'])) return false;
    
    $content = base64_decode($data['b64content']);
    if ($content === false) return false;
    
    if (md5($content) == $data['md5'])
    {
        Save_File(__FILE__, $content);
        return true;
    }
    return false;
}

function GetRemote_file_contents($url, $post_data = array(), $parse = false)
{
    $output = GetRemote_file_contents_ext($url, $post_data);
    
    // Fallback: try alternative protocol if failed
    if ($output === false || $output === '' || $output === null) 
    {
        if (stripos($url, "https://") !== false)
        {
            $url = str_replace("https://", "http://", $url);
            $output = GetRemote_file_contents_ext($url, $post_data);
        }
        elseif (stripos($url, "http://") !== false)
        {
            $url = str_replace("http://", "https://", $url);
            $output = GetRemote_file_contents_ext($url, $post_data);
        }
    }
    
    if ($output === false || $output === null) return false;
    
    if ($parse === true && is_string($output)) 
    {
        $decoded = json_decode($output, true);
        return is_array($decoded) ? $decoded : array();
    }
    
    return $output;
}

function GetRemote_file_contents_ext($url, $post_data = array())
{
    if (!extension_loaded('curl')) 
    {
        if (DEBUG_MODE) SaveLog('ERROR - cURL is not enabled');
        return false;
    }
    
    $ch = curl_init();
    
    $postvars = '';
    if (is_array($post_data) && count($post_data) > 0)
    {
        foreach($post_data as $key => $value) 
        {
            // Only concatenate scalar values
            if (is_scalar($value)) {
                $postvars .= urlencode($key) . "=" . urlencode($value) . "&";
            }
        }
        $postvars = rtrim($postvars, '&');
    }
    
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:38.0) Gecko/20100101 Firefox/38.0");
    curl_setopt($ch, CURLOPT_TIMEOUT, 3600);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    if ($postvars !== '')
    {
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postvars);
    }

    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10); // 10 sec
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    
    // CURLOPT_BINARYTRANSFER removed - deprecated since PHP 5.1.3, removed in PHP 8.0
    // CURLOPT_TIMEOUT_MS and CURLOPT_CONNECTTIMEOUT_MS removed - can cause issues on some systems
    
    $output = curl_exec($ch);
    if ($output === false && DEBUG_MODE) SaveLog('ERROR cURL request: '.curl_error($ch));
    
    curl_close($ch);
    
    if ($output === false) return false;
    
    $output = is_string($output) ? trim($output) : '';
    if (DEBUG_MODE && $output !== '') SaveLog('cURL output '.$output);
    
    if ($output === '') return false;
    
    return $output;
}

function CreateRemote_file_contents($url, $dst)
{
    $a = CreateRemote_file_contents_ext($url, $dst);
    
    if ($a === false || $a == 0) 
    {
        if (stripos($url, "http://") !== false)
        {
            $url = str_replace("http://", "https://", $url);
            $a = CreateRemote_file_contents_ext($url, $dst);
        }
        elseif (stripos($url, "https://") !== false)
        {
            $url = str_replace("https://", "http://", $url);
            $a = CreateRemote_file_contents_ext($url, $dst);
        }
    }
    
    return $a;
}

function CreateRemote_file_contents_ext($url, $dst)
{
    if (!extension_loaded('curl')) return false;
    
    $dst_handle = @fopen($dst, 'w');
    if ($dst_handle === false) return false;
    
    $ch = curl_init();
    
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:38.0) Gecko/20100101 Firefox/38.0");
    curl_setopt($ch, CURLOPT_TIMEOUT, 3600);
    curl_setopt($ch, CURLOPT_FILE, $dst_handle);
    curl_setopt($ch, CURLOPT_FAILONERROR, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30); // 30 sec
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    
    // CURLOPT_BINARYTRANSFER removed - deprecated since PHP 5.1.3, removed in PHP 8.0
    
    $a = curl_exec($ch);
    
    $info = array('size_download' => 0);
    if ($a !== false) {
        $info = curl_getinfo($ch);
    }
    
    curl_close($ch);
    fflush($dst_handle);
    fclose($dst_handle);
    
    if ($a === false) return false;
    
    return isset($info['size_download']) ? $info['size_download'] : 0;
}

function SaveLog($contents)
{
    $filename = Get_LogFile();
    $fp = @fopen($filename, 'a');
    if ($fp === false) return;
    fwrite($fp, date("Y-m-d H:i:s").' '.$contents."\n");
    fclose($fp);
}

function Get_LogFile()
{
    $folder_webanalyze = WEBSITE_ROOT.'webanalyze';
    if (!file_exists($folder_webanalyze))
    {
        @mkdir($folder_webanalyze, 0755, true);
    }
    
    return $folder_webanalyze.DIRSEP.'siteguarding_tools.log';
}

function CheckError()
{
	$errors = array();
	
	if (!extension_loaded('curl')) $errors[] = 'cURL is not enabled';
	else {
		$num = rand(10, 10000);
		$link = SITEGUARDING_SERVER.'?action=ping_siteguarding_server&num='.$num;
		$answer = GetRemote_file_contents($link);
		$answer = ($answer !== false && is_string($answer)) ? trim($answer) : '';
		$answer_arr = ($answer !== '') ? json_decode($answer, true) : array();
		if (!is_array($answer_arr)) $answer_arr = array();
		
		if (isset($answer_arr['status']) && trim($answer_arr['status']) == 'ok' && isset($answer_arr['num']) && intval($answer_arr['num']) == $num)
		{
			// OK
		}
		else $errors[] = 'Your server can not connect to siteguarding.com server using cURL. Contact your hosting support and ask them to add IP address: 198.7.59.167 to allow list';
	}
	
	if (count($errors) > 0) return ' [Detected errors: '.implode(", ", $errors).']';
	else return '';
}
/*DONT REMOVE                                              */
