rule Win_Trojan_Pakes_412
{
strings:
	$a0 = { fd9c37424c080f12c006e80649fa075161e26cda64ccded9686fb6f6737cf70fd43bf418db29fa9564f1af16d9f298e7aa3e002aa13ff243f4ddf7c8c92a5a3b9a7cdf12c1cb08b87ff8ec07dff171ec412265effd045dc934547bf68faee97b31f2e385e5f30caef8b07c7342241b15cd0a7d4ac6004a14a45748d376923e158f013baadd2131e4620042ad }

condition:
	$a0
}

        