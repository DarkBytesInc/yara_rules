rule Win_Trojan_Mybot_7803
{
strings:
	$a0 = { 7412d51b9bc55bca425c6e05966c5aa86ed698050c6de97aac6ae1dc56e39e6f9196fb30ef4e163cd8a52e209d96a839815535da511b95321b619696fa442cff79b6e42dd8b9c87fccb394231d5218eb575968a6450d85da73763c193c571e07c212e6ab13cf98d880be9222efeda4ef675207099199510a3fc07eac0d04775e5b9ddbb5d27e4f075b9c69454983f3a8 }

condition:
	$a0
}

        