<?php
        $realm = 'Restricted area';

        //user => password
        $users = array('admin' => 'mypass', 'guest' => 'guest');


        if (empty($_SERVER['PHP_AUTH_DIGEST'])) {
			$nonce = uniqid(); //pode ser guardado no servidor para evitar ataque de replay

            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: Digest realm="'.$realm.
            '",qop="auth",nonce="'. $nonce .'",opaque="'.md5($realm).'"');

            die('Failed');
        }


        // analisa a variavel PHP_AUTH_DIGEST
        if (!($data = http_digest_parse($_SERVER['PHP_AUTH_DIGEST'])) ||
            !isset($users[$data['username']]))
            die('Credenciais invalidas!');


        // gera uma resposta valida
		// $data['username'] -> usuario       e       $users[$data['username']] -> senha
        $A1 = md5($data['username'] . ':' . $realm . ':' . $users[$data['username']]);
        $A2 = md5($_SERVER['REQUEST_METHOD'].':'.$data['uri']);
        $valid_response = md5($A1.':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.$A2);

        if ($data['response'] != $valid_response) {
	        die('Credenciais invalidas!');
		}
		else {
		    // ok, username e password validos
	        // echo 'Your are logged in as: ' . $data['username'] . $data['nc'];
			$file = 'capa.gif';

			if (file_exists($file)) {
				//carrega o asset desejado
				if (strpos($file, '.gif'))
					header('Content-Type: image/gif');
				if (strpos($file, '.jpg') || strpos($file, '.jpeg'))
					header('Content-Type: image/jpg');
				if (strpos($file, '.pdf'))
					header('Content-Type: application/pdf');
				header("Content-Transfer-Encoding: binary");
				header("Content-Length: ".filesize($file));
				ob_clean();
				flush();
				readfile($file);
			}
			
		
		}


        // funcao para renderizar o http auth header
        function http_digest_parse($txt)
        {
            // protege contra dados inexistentes, remove o auxiliar e inclui o real com o unset
            $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
            $data = array();


			foreach (preg_split('/\s*,\s*/', $txt) as $i => $term){
				if (preg_match("@(\w+)=(?:(['\"])?)([\/\.\w]+\s*\w+)@",$term, $M)) {
					$data[$M[1]] = $M[3] ? $M[3] : "";
					unset($needed_parts[$M[1]]);
				}
			}

            return $needed_parts ? false : $data;
        }
    ?>