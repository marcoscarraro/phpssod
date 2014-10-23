phpssod
=======

ATENÇÃO:
Devido a complexidade por criar o ssod, e por não saber se ele funciona em outras versões, achei melhor utilizar a API da microsoft para desenvolver a DLL que fará o hook das senhas a qual esta neste projeto **https://github.com/marcoscarraro/SyncPass**

phpssod baseado em perlssod https://github.com/ZeWaren/pSSOd/ daemon que recebe as senhas do active direcory. Depois podendo replicar para outras bases

Crédidos para http://zewaren.net/site/ que me passou a lógica do pssod.

O programa recebe a notificação do AD, este pacote esta criptografado utilizando 3DES, onde tem uma chave compartilhada, então o php faz todo processo e descriptografa a senha e o login do usuário, ideal para depois você utilizar no seu sistema.

