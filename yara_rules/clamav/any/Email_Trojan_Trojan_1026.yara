rule Email_Trojan_Trojan_1026
{
strings:
	$a0 = { 54686520666f6c6c6f77696e672041434820626174636820686173206265656e207375626d697474656420666f722070726f63657373696e67[134-144]506c656173652076696577207468652061747461636865642066696c6520746f2072657669657720746865207472616e73616374696f6e2064657461696c }

condition:
	$a0
}

        