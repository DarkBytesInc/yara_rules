rule Win_Trojan_SillyC_80
{
strings:
	$a0 = { cd21cd2090907d474f41542046696c652047656e657261746f7220312e303020fe2028632920313939342d393620627920524f53452c2052616c706820526f74682120202832392e30392e31393936290d0a46696c653a20524f53453030332e434f4d202d20382e36303020283231393868 }

condition:
	$a0
}

        