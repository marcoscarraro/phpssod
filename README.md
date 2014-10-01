phpssod
=======

phpssod baseado em perlssod https://github.com/ZeWaren/pSSOd/ daemon que recebe as senhas do active direcory. Depois podendo replicar para outras bases

Crédidos para http://zewaren.net/site/ que me passou a lógica do pssod.

O programa recebe a notificação do AD, este pacote esta criptografado utilizando 3DES, onde tem uma chave compartilhada, então o php faz todo processo e descriptografa a senha e o login do usuário, ideal para depois você utilizar no seu sistema.

