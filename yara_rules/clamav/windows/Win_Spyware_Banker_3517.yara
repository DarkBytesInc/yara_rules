rule Win_Spyware_Banker_3517
{
strings:
	$a0 = { 011e17f83798646921ce084c28c35ac9e7ebcc2a543b607a4470da5cb5864bf208837425a435e9b5ca25bdc8486c08fcabd44775a2e51fcdf9653e133a573194478a09362a5c31efe8bf2ce4405075e3582502673be43629c3710223614966ef3a680890a387b0eb12dcda28d44a4eda }

condition:
	$a0
}

        