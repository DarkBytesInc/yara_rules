rule Win_Spyware_Banker_1475
{
strings:
	$a0 = { 6bbb1252e0325d42f3259981cade36859c06a3e459a83226a1d7bcbbcc5f8a389475292445333c045f99db91b28ba84c2f148176d8a3125ccbb8afa0a12e81cd5cf13f8cbbb02c1412ac7efb047f006448f304e970384be664ce99cc87e4360e3fe6701ba7c52cc0be682d2e9d43e08d3991a8ef81baaf784b5719e20cbfdf7ce130b4fa8e364c2e13c5355fa8189f9fde3c3b299065 }

condition:
	$a0
}

        