### Para a sala de chat criptografada

Antes de implementar o código, recomendamos que o candidato estude o protocolo Diffie-Hellman para troca de chaves.

**Nenhum arquivo deve ser alterado, exceto o `key_protocol.py`.** Leia atentamente os comentários contidos neste arquivo.

Observe que alguns passos do protocolo que será implementado já estão descritos. Na função `exchange_keys_server(client_socket, p, g, s, enc_msg, conf_msg)`, já temos:
- Os valores utilizados no Diffie-Hellman: `p` e `g`;
- O valor secreto do servidor: `s`;
- A mensagem escolhida (`conf_msg`) e seu texto cifrado (`enc_msg`) para confirmar a validade da execução da troca de chaves.

Após implementar a troca de chaves, para executar o código, rode o arquivo `main.py`.

---

### Para o código de computação quântica

Antes de implementar o código, recomendamos que o candidato estude o algoritmo de Shor.

**Nenhum arquivo deve ser alterado no código base do projeto quântico, exceto o `FindPeriod.ipynb`.**  
O objetivo é implementar o código para determinar o período das seguintes funções:  
- \( f(x) = 15^x \mod 31 \)
- \( f(x) = 2^x \mod 31 \)  
Ambas as funções são definidas como \( \mathbb{Z} \rightarrow \mathbb{Z} \).

O candidato pode usar as porta controladas: c_exp_2_mod31 e c_exp_15_mod31 fornecidos no código base. c_exp_2_mod31 implementa \( 2^x \mod 31 \)  e c_exp_15_mod31 \( 15^x \mod 31 \) .

---

### Avisos gerais

As atividades propostas ao candidato têm como objetivo não apenas avaliar a implementação, mas também:  
- Introduzi-lo à área de computação quântica aplicada à criptografia e criptoanálise;  
- Acrescentar a experiência proporcionada por este projeto seu currículo;  
- Estimular a proatividade na pesquisa sobre os temas abordados;  
- Analisar sua capacidade de trabalhar em equipe, interagindo com outros candidatos, esclarecendo dúvidas, sugerindo melhorias, etc.

O empenho demonstrado pelo candidato nos aspectos mencionados poderá ser considerado como critério de avaliação.

Caso o candidato encontre algum **problema no código base** de qualquer uma das partes do projeto, poderá solicitar **auxílio aos membros da Liga**.

Não esqueça de criar um arquivo contendo as explicações solicitadas.
