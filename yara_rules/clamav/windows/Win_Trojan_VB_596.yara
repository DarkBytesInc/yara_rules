rule Win_Trojan_VB_596
{
strings:
	$a0 = { 0f483541fe1b5f46c01ea415c53246ffe5023d851ee63436b6f5c4a59f3b95036d1cde453c70543b89db1d697c1478759d29589a051fb00e879cf316333d15e0071471318d341d3c0915d7283c4176a6e557440834453d961017259bfefa340e1157f75b22495506241bdb4b143ce20d75fb0510ed774b0848351d802002099442676571e5568cc582476886 }

condition:
	$a0
}

        