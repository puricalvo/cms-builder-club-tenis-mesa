<?php 

require_once "models/get.model.php";
require_once "models/post.model.php";
require_once "models/connection.php";

require_once "vendor/autoload.php";
use Firebase\JWT\JWT;

require_once "models/put.model.php";

class PostController{

	/*=============================================
	Peticion POST para crear datos
	=============================================*/

	static public function postData($table, $data){

		$response = PostModel::postData($table, $data);
		
		$return = new PostController();
		$return -> fncResponse($response,null,null);

	}

	/*=============================================
	Peticion POST para registrar usuario
	=============================================*/

	static public function postRegister($table, $data, $suffix){

		if(isset($data["password_".$suffix]) && $data["password_".$suffix] != null){

			$crypt = crypt($data["password_".$suffix], $_ENV["PASSWORD_SALT"]);

			$data["password_".$suffix] = $crypt;

			$response = PostModel::postData($table, $data);

			$return = new PostController();
			$return -> fncResponse($response,null,$suffix);

		}else{

			/*=============================================
			Registro de usuarios desde APP externas
			=============================================*/

			$response = PostModel::postData($table, $data);

			if(isset($response["comment"]) && $response["comment"] == "The process was successful" ){

				/*=============================================
				Validar que el usuario exista en BD
				=============================================*/

				$response = GetModel::getDataFilter($table, "*", "email_".$suffix, $data["email_".$suffix], null,null,null,null);
				
				if(!empty($response)){		

					$token = Connection::jwt($response[0]->{"id_".$suffix}, $response[0]->{"email_".$suffix});

					
					$jwt = JWT::encode($token, $_ENV["JWT_SECRET"], "HS256");

					/*=============================================
					Actualizamos la base de datos con el Token del usuario
					=============================================*/

					$data = array(

						"token_".$suffix => $jwt,
						"token_exp_".$suffix => $token["exp"]

					);

					$update = PutModel::putData($table, $data, $response[0]->{"id_".$suffix}, "id_".$suffix);

					if(isset($update["comment"]) && $update["comment"] == "The process was successful" ){

						$response[0]->{"token_".$suffix} = $jwt;
						$response[0]->{"token_exp_".$suffix} = $token["exp"];

						$return = new PostController();
						$return -> fncResponse($response, null,$suffix);

					}

				}


			}


		}

	}



	static public function postLogin($table, $data, $suffix){

    // Buscar administrador por correo
    $response = GetModel::getDataFilter(
        $table,
        "*",
        "email_".$suffix,
        $data["email_".$suffix],
        null,
        null,
        null,
        null
    );

    if(!empty($response)){

        // No permitir acceso sin contraseña
        if(
            !isset($data["password_".$suffix]) ||
            trim($data["password_".$suffix]) === "" ||
            empty($response[0]->{"password_".$suffix})
        ){

            $return = new PostController();
            $return->fncResponse(null, "Wrong email or password", $suffix);
            return;
        }

        // Comprobar contraseña
        $crypt = crypt(
            $data["password_".$suffix],
            $_ENV["PASSWORD_SALT"]
        );

        if($response[0]->{"password_".$suffix} !== $crypt){

            $return = new PostController();
            $return->fncResponse(null, "Wrong email or password", $suffix);
            return;
        }

        // Comprobar estado del administrador
        if($suffix == "admin" && (int)$response[0]->status_admin !== 1){

            $return = new PostController();
            $return->fncResponse(null, "Administrator disabled", $suffix);
            return;
        }

        // Generar token únicamente después de validar contraseña
        $token = Connection::jwt(
            $response[0]->{"id_".$suffix},
            $response[0]->{"email_".$suffix}
        );

        $jwt = JWT::encode($token, $_ENV["JWT_SECRET"], "HS256");

        $dataToken = array(
            "token_".$suffix => $jwt,
            "token_exp_".$suffix => $token["exp"]
        );

        $update = PutModel::putData(
            $table,
            $dataToken,
            $response[0]->{"id_".$suffix},
            "id_".$suffix
        );

        if(
            isset($update["comment"]) &&
            $update["comment"] == "The process was successful"
        ){

            $response[0]->{"token_".$suffix} = $jwt;
            $response[0]->{"token_exp_".$suffix} = $token["exp"];

            $return = new PostController();
            $return->fncResponse($response, null, $suffix);
            return;
        }

        $return = new PostController();
        $return->fncResponse(null, "Token generation failed", $suffix);
        return;

    }

    $return = new PostController();
    $return->fncResponse(null, "Wrong email or password", $suffix);
}

	
	/*=============================================
	Respuestas del controlador
	=============================================*/

	public function fncResponse($response,$error,$suffix){

		if(!empty($response)){

			/*=============================================
			Quitamos la contraseña de la respuesta
			=============================================*/

			if(isset($response[0]->{"password_".$suffix})){

				unset($response[0]->{"password_".$suffix});

			}

			$json = array(

				'status' => 200,
				'results' => $response

			);

		}else{

			if($error != null){

				$json = array(
					'status' => 400,
					"results" => $error
				);

			}else{

				$json = array(

					'status' => 404,
					'results' => 'Not Found',
					'method' => 'post'

				);
			}

		}

		echo json_encode($json, http_response_code($json["status"]));

	}

}