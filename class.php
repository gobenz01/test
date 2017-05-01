<?php
@include("config.php");
class UsersClass {
	private $DB;
	
	function __construct(){
		$this->checkaccess();
		$this->DB = $this->getDB();
		if(!isset($_SESSION['failed_login'])){
				$_SESSION['failed_login'] = 0;
		}
	}
	
	public function GetMasterKey($key){
			$list = array('a','b','c','d','e','f');
			$k = $key;
			for($i=0; $i<strlen($list); $i++){
				$k = str_replace($list[$i], '', $k);
			
			$re = $this->removeDuplicateChar($k);
			
			return $re;
			
		}
		
		
	public function removeDuplicateChar($str) { 
		assert(is_string($str)); 
		
		$start = 0 ; 
		$end = strlen($str) -1;
		
	 
		while ($start < $end  ) { 
			
			$isDuplicateFound = false; 
			
			for($second =  $start +1 ; $second <= $end ; $second ++ ) { 
				
				if($str[$start] == $str[$second]){ 
					$isDuplicateFound  = true;
					break;      
				}
			}
			 
		  
			if($isDuplicateFound) {             
				for($rev = $second ; $rev < $end; $rev++) {
					$str[$rev] = $str[$rev +1];
				}
				
				$str[$rev]  = null;
				$str = trim($str);
				$end = strlen($str)-1;
			   
			} else { 
				 $start ++ ;
			}
			
		}
		
		return $str ; 
    
	}
	
	public function getDB(){
		$DB_HOST = 'localhost';
		$DB_USER = 'root';
		$DB_PASS = '';
		
		try {
			$DB_CON = new PDO('mysql:host=localhost;dbname=bnzus_infosec',$DB_USER,$DB_PASS);
			$DB_CON->exec("set names utf8");
			$DB_CON->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		}catch(PDOException $e) {
			echo "Error: " . $e->getMessage();
		}
		
		return $DB_CON;
	}
	
	protected function checkaccess(){
			//IF BLOCK BY IP IS ENABLED
			if(BLOCK_IP==true){
				$block_ip_data = json_decode(@file_get_contents("blockedip.json"),true);
				//print_r($block_ip_data);exit;
				if(count($block_ip_data)>0) {
					foreach($block_ip_data as $key=>$blocked_ip){
						if($_SERVER['REMOTE_ADDR']==$blocked_ip['ip_address']){
							if($blocked_ip['timeout']>date("Y-m-d H:i:s")){
								@header("location:blocked.html");
								exit;
							} else {
								unset($block_ip_data[$key]);
								@header("location:index.php");
								file_put_contents("blockedip.json",json_encode($block_ip_data));
							}
							break;
						}
					}
				}
			}
	}
	
	public function saveLoginDetails($username){
			$stmt = $this->DB->prepare("INSERT INTO loginhistory (username, ip, datetime) VALUES (:username, :ip, :datetime)");
			$stmt->bindParam(':username', $username);
			$stmt->bindParam(':ip', $_SERVER['REMOTE_ADDR']);
			$stmt->bindParam(':datetime', date("Y-m-d H:i:s"));
			$stmt->execute();
			return true;
	}

	public function checkSession($type){
	$user_id = $_SESSION['user_id'];
	$user_type = $_SESSION['user_type'];
		if(strcmp($type,"director") == 0){
				if ($user_id == "" || $user_type == "") {
					echo "<script type='text/javascript'>alert('Session is Expire. Please Login !'); window.location.href = 'index.php';</script>";
					exit();
				}else if($user_type != 0){
					echo "<script type='text/javascript'>alert('Permission denied !'); window.location.href = 'index.php';</script>";
					exit();
				}
		}else if(strcmp($type,"personnel") == 0){
				if ($user_id == "" || $user_type == "") {
					echo "<script type='text/javascript'>alert('Session is Expire. Please Login !'); window.location.href = 'index.php';</script>";
					exit();
				}else if($user_type != 1){
					echo "<script type='text/javascript'>alert('Permission denied !'); window.location.href = 'index.php';</script>";
					exit();
				}
		}else if(strcmp($type,"staff") == 0){
				if ($user_id == "" || $user_type == "") {
					echo "<script type='text/javascript'>alert('Session is Expire. Please Login !'); window.location.href = 'index.php';</script>";
					exit();
				}else if($user_type != 2){
					echo "<script type='text/javascript'>alert('Permission denied !'); window.location.href = 'index.php';</script>";
					exit();
				}
		}else if(strcmp($type,"admin") == 0){
				if ($user_id == "" || $user_type == "") {
					echo "<script type='text/javascript'>alert('Session is Expire. Please Login !'); window.location.href = 'index.php';</script>";
					exit();
				}else if($user_type != 3){
					echo "<script type='text/javascript'>alert('Permission denied !'); window.location.href = 'index.php';</script>";
					exit();
				}
		}
	}
//director // 0
//personnel // 1
//staff // 2
	public function checkSessionLoginPage(){
		if(isset($_SESSION['user_type']) && isset($_SESSION['user_id'])){
					if($_SESSION['user_type'] == 0 )
						@header("location:main.php?role=director");
					else if($_SESSION['user_type'] == 1)
						@header("location:main.php?role=personnel");
					else if($_SESSION['user_type'] == 2)
						@header("location:main.php?role=staff");
					else if($_SESSION['user_type'] == 3)
						@header("location:admin.php");
					exit;
		}
		
	}
	
	public function UpdateProfile($id,$role,$password){
			if($password == ''){
				$stmt = $this->DB->prepare("update users SET users_status = :role WHERE users_id = :id");
				$stmt->bindParam(':role', $role, PDO::PARAM_INT);
				$stmt->bindParam(':id', $id, PDO::PARAM_STR);
				$stmt->execute();
			}else{
				$pass = $this->encryptPassword($password);
				$stmt = $this->DB->prepare("update users SET users_status = :role, users_password = :pass WHERE users_id = :id");
				$stmt->bindParam(':pass', $pass, PDO::PARAM_STR);
				$stmt->bindParam(':role', $role, PDO::PARAM_INT);
				$stmt->bindParam(':id', $id, PDO::PARAM_STR);
				$stmt->execute();

			}
			return true;
	}
	
	public function Login($username,$password,$recap){ // -3 Login Fail || -2 Capcha Wrong
		if($recap){ // IF capcha is True
			$pass = $this->encryptPassword($password);
			$stmt = $this->DB->prepare("SELECT * FROM users WHERE users_username = :user AND users_password = :pass");
			$stmt->bindParam(':user', $username, PDO::PARAM_STR);
			$stmt->bindParam(':pass', $pass, PDO::PARAM_STR);
			$stmt->execute();
			$rows = $stmt->fetch(PDO::FETCH_OBJ);
			if($stmt->rowCount() >= 1){ // Login Success
					$_SESSION['failed_login'] = 0;
					$_SESSION['user_id'] = $username;
					$_SESSION['user_type'] = $rows->users_status;
					$this->saveLoginDetails($username); // Save History Login
					if($rows->users_status == 0 )
						@header("location:main.php?role=director");
					else if($rows->users_status == 1)
						@header("location:main.php?role=personnel");
					else if($rows->users_status == 2)
						@header("location:main.php?role=staff");
					else if($rows->users_status == 3)
						@header("location:admin.php");
					exit;
			}else{ // Login Fail
					$_SESSION['failed_login']++;
					if($_SESSION['failed_login']>= 2){
						return -4;
						
					}
					if($_SESSION['failed_login']>=MAX_LOGIN_ATTEMPT){

						//IF BLOCK BY IP IS ENABLED
						if(BLOCK_IP===true){
							$block_ip_data = json_decode(@file_get_contents("blockedip.json"),true);
							$block_ip_data[] = array(
												"ip_address"=>$_SERVER['REMOTE_ADDR'],
												"timeout"=>date("Y-m-d H:i:s",strtotime(date("Y-m-d H:i:s")."+".BLOCK_TIMEOUT." Minutes"))
												);
							file_put_contents("blockedip.json",json_encode($block_ip_data));
							$_SESSION['failed_login'] = 0;
						}
					}
					return -3;
					@header("location:index.php");
					
					exit;
			}
		}else{
			return -2;
		}
	}
	
	public function Signup($username,$password,$firstname,$lastname,$telephone){
		if($this->isExistingUser($username)){
			return false;
		}else{
			$pass = $this->encryptPassword($password);
			$stmt = $this->DB->prepare("INSERT INTO users (users_username, users_password, users_firstname, users_lastname, users_tel) VALUES (:user, :pass, :firstname, :lastname, :tel)");
			$stmt->bindParam(':user', $username, PDO::PARAM_STR);
			$stmt->bindParam(':pass', $pass, PDO::PARAM_STR);
			$stmt->bindParam(':firstname', $firstname, PDO::PARAM_STR);
			$stmt->bindParam(':lastname', $lastname, PDO::PARAM_STR);
			$stmt->bindParam(':tel', $telephone, PDO::PARAM_STR);
			//$stmt->bindParam(':status', 1, PDO::PARAM_INT);
			$stmt->execute();
			return true;
		}
	}
	
	public function encryptPassword($password){

				//$string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_{|}~--------";
				$string = "4STUVrstu5678yz01E9ab,-./:pqdefghvMN;<=>cWijklm23ABCDnowxZ!\"#$%&'(FGHPQRXY)IJKLO*+?@[\]^_{|}~4STUVr";
				$out = "";
				$in = 0;
				$sum = 0;
				for($i=0; $i<strlen($password); $i++){
				   $in = $this->getIndexs($password[$i]);
			 $sum = $in+5;
				   //$out .= $sum.' ';
				  
				  $out .= $string[$sum];
				   
				}
			   $out2 = '';
			 $out2 = strrev($out); 
				
			  return $out2;
	}
	
	public function isWeakPassword($pwd){
		
		if (strlen($pwd) < 8) {
			return true;
		}else if (!preg_match("#[0-9]+#", $pwd)) {
			return true;
		}else if (!preg_match("#[a-zA-Z]+#", $pwd)) {
			return true;
		}else if( !preg_match("#\W+#", $pwd) ) {
			return true;
		}else{
			return false;
		}

	}
	
	public function isExistingUser($username){
		$stmt = $this->DB->prepare("SELECT * FROM users WHERE users_username = :user");
		$stmt->bindParam(':user', $username, PDO::PARAM_STR);
		$stmt->execute();
		if($stmt->rowCount() >= 1){
			return true;
		}else{
			return false;
		}
	}
	
	public function DelUser($id){
			$stmt = $this->DB->prepare("DELETE FROM users WHERE users_id = :id");
			$stmt->bindParam(':id', $id, PDO::PARAM_INT);
			$stmt->execute();
			return true;
	}
	
	public function ShowAllUser(){
		$stmt = $this->DB->prepare("SELECT * FROM users");
		$stmt->execute();
		$re = $stmt->fetchAll(PDO::FETCH_ASSOC);
		foreach ($re as $row){
			if($row['users_status'] == 1){
				$showRole = 'Personel';
			}else if($row['users_status'] == 2){
				$showRole = 'Staff';
			}else if($row['users_status'] == 3){
				$showRole = 'Admin';
			}else if ($row['users_status'] == 0){
				$showRole = 'Director';
			}
			echo '<tr>';
			echo '<td>'.$row['users_id'].'</td>';
			echo '<td>'.$row['users_firstname'].' '.$row['users_lastname'].'</td>';
			echo '<td>'.$row['users_username'].'</td>';
			echo '<td>'.$row['users_tel'].'</td>';
			echo '<td>'.$showRole.'</td>';
			echo '<td><a href="edit.php?id='.$row['users_id'].'" ><button class="btn btn-icon waves-effect waves-light btn-warning m-b-5"> <i class="fa fa-pencil"></i> </button></a> <td><a href="del.php?id='.$row['users_id'].'" onclick="return confirm("Are you sure?")"><button class="btn btn-icon waves-effect waves-light btn-warning m-b-5"> <i class="fa fa-trash-o"></i> </button></a><td>';
			echo '</tr>';
		}
		
		return true;
		
	}
	
	
	public function getIndexs($x){
	$string = "4STUVrstu5678yz01E9ab,-./:pqdefghvMN;<=>cWijklm23ABCDnowxZ!\"#$%&'(FGHPQRXY)IJKLO*+?@[\]^_{|}~4STUVr";
    for($i=0; $i<strlen($string); $i++){
        if(strcmp($string[$i],$x) == 0){
            $index = $i;
            break;
        }
    }
    
    return $index;
	
	}
	
	public function ShowAllLog(){
		$stmt = $this->DB->prepare("SELECT * FROM loginhistory");
		$stmt->execute();
		$re = $stmt->fetchAll(PDO::FETCH_ASSOC);
		foreach ($re as $row){
			echo '<tr>';
			echo '<td>'.$row['id'].'</td>';
			echo '<td>'.$row['username'].'</td>';
			echo '<td>'.$row['ip'].'</td>';
			echo '<td>'.$row['datetime'].'</td>';
			echo '</tr>';
		}
		
		return true;
		
	}
	
}
 
?>
