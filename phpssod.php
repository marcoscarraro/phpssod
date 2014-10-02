#!/usr/bin/php -q
<?php
/*
Autor do script em Perl: Erwan Martin http://zewaren.net/site/

Autor do script em php: Marcos Carraro marcos.g.carraro@gmail.com http://marcoscarraro.blogspot.com/



Como funciona o SSOD da microsoft, tudo é transferido em formato binário, então para poder ler devemos quebrar no formato que desejarmos

Active directory conecta no servidor socket e então...
- php envia uma string aleatoria de 8bytes para o ad em formato binário

Logo o ad retorna na sequencia
- Versão do protocolo
- Tamanho da mensagem
- Tipo da mensagem
- String aletória do gerada pelo AD, que foi usada para encriptar a mensagem
- A mensagem

Agora então você cria a chave DES utilizando a string enviada pelo php, a strig recebida do AD, e a chave compartilhada entre AD e PHP, então a mensagem se quebra em 3 partes
- Login do Usuário
- Senha
- Um hash de verificação da veracidade do pacote

Termina a troca de informação

Obs:. Existem alguns retornos de sucesso e erro, estes devem ser enviados para o AD ao término da operação, e em falhas da operação.

Ex:. Retorono de sucesso
 $sucess = 0;
 $tamanho_sucesso = strlen($sucess);
 $string_sucesso = pack('C*', $sucess);
 $envia_sucesso = socket_send($sockt_server, $string_sucesso, $tamanho_sucesso, 0);

 ERROR_SUCCESS => 0;
 ERROR_FILE_NOT_FOUND => 1;
 ERROR_LOCK_VIOLATION => 2;
 ERROR_CANNOT_OPEN_FILE => 3;
 ERROR_PASSWORD_NOT_UPDATED => 4;
 ERROR_PROTOCOL => 5;
 ERROR_BAD_USER_NAME => 6;
 ERROR_DECRYPTING => 7;
 ERROR_VERSION_NOT_SUPPORTED => 8;
 ERROR_BAD_PASSWORD => 9;
 ERROR_CANNOT_MAKE_MAPS => 10;
 ERROR_WRITE_FAULT => 11;
 ERROR_NO_USER_ENTRY => 12;
 ERROR_USER_LOGIN_DISABLED => 13;
 ERROR_USER_REFUSED => 14;
 ERROR_PASSWORD_EXPIRED => 15;
 ERROR_PASSWORD_CANT_CHANGE => 16;
 ERROR_HISTORY_CONFLICT => 17;
 ERROR_TOO_SHORT => 18;
 ERROR_TOO_RECENT => 19;
 ERROR_BAD_PASSWORD_FILE => 20;
 ERROR_BAD_SHADOW_FILE => 21;
 ERROR_COMPUTING_LASTCHG_FIELD => 22;
 ERROR_VERSION_NUMBER_MISMATCH => 23;
 ERROR_PASSWORD_LENGTH_LESS => 24;
 ERROR_UPDATE_PASSWORD_FILE => 25;
 LAST_ERROR_NUMBER => 25;

*/
error_reporting(E_ALL);
/* Tempo ilimitado para executar o script*/
set_time_limit(0);
/* limpa o buffer a cada operação */
ob_implicit_flush();

/* IP e porta para escuta */
$address = '192.168.1.222';
$port = 6677;

if (($sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false) {
    echo "socket_create() failed: reason: " . socket_strerror(socket_last_error()) . "\n";
}

 if (!socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1)) {
    echo "socket_set_option() failed: reason: " . socket_strerror(socket_last_error($sock)) . "\n";
    exit;
} 

if (socket_bind($sock, $address, $port) === false) {
    echo "socket_bind() failed: reason: " . socket_strerror(socket_last_error($sock)) . "\n";
}

if (socket_listen($sock, 5) === false) {
    echo "socket_listen() failed: reason: " . socket_strerror(socket_last_error($sock)) . "\n";
}


/* While para tratar as conexões */
while (true) {
    if (($sockt_server = socket_accept($sock)) === false) {
        echo "socket_accept() failed: reason: " . socket_strerror(socket_last_error($sock)) . "\n";
        break;
    }
	
	/* String aleatório de 8bytes*/
	$string_1 = '';
	for ($x = 1; $x <= 8; $x++){
		$string_1 .=rand(0,255);
	}
    $tamanho_string_1 = strlen($string_1);
	/* Converter a string para uma string de caracteres sem definição*/
	$string_1 = pack('C*', $string_1);
	/* Transforma a string_1 em binário de 8bytes*/
	$string_1 = pack("A8", $string_1);
	$string_1_uso = unpack("N", $string_1);
	$string_1_uso = $string_1_uso[1];
    $envia_string_1 = socket_send($sockt_server, $string_1, $tamanho_string_1, 0);
    
	

	/* Retorno do AD com a versão do protocolo com 4 bytes*/
    $versao_pacote_buf = '';
    $retorno_versao_pacote = socket_recv($sockt_server, $versao_pacote_buf, 4, 0);
	$versao_pacote = unpack("N", $versao_pacote_buf);
	$versao_pacote = $versao_pacote[1];
    if ($versao_pacote != 0) {
        echo "versão do pacote desconhecida \n";
		$erro_processo = 8;
    }
    
	
	/* Retorno do AD com o tamanho da mensagem */
    $tamanho_msg_buf = '';
    $retorno_tamanho_msg = socket_recv($sockt_server, $tamanho_msg_buf, 4, 0);
	$tamanho_msg = unpack("N", $tamanho_msg_buf);
	$tamanho_msg = $tamanho_msg[1];
    
	
	
	/* Retorno do AD conteudo da mensagem, no caso a mensagem! */
	$msg_buf = '';
	$tamanho_msg_buf = $tamanho_msg - 8;
    $retorno_msg = socket_recv($sockt_server, $msg_buf, $tamanho_msg_buf , 0);

	$a = unpack('Ntipo/A8string_2/A*pacote', $msg_buf );
	// Tipo MSG
	$tipo_msg = $a['tipo'];
	
	// String AD
	$string_2 = unpack('N',$a['string_2']);
	$string_2 = $string_2[1];
	
	// Conteudo do pacote
	$conteudo_pacote = $a['pacote'];
	
	
	
	
	
	/* Retorno para o AD que concluimos com sucesso a tarefa*/
	$version_number = 0;
  $message_type = 1;
  $message_size = 4*4;
	$error = 0;
	$tamanho_response = strlen($version_number.$message_type.$message_size.$error);
  $response_buffer = pack("NNNN", $version_number, $tamanho_response, $message_type, $error);   
	$envia_string_1 = socket_send($sockt_server, $response_buffer, $message_size, 0);

	
    socket_close($sockt_server);
};

socket_close($sock);
?>
