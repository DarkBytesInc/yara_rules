rule Doc_Trojan_ZMK_7
{
strings:
	$a0 = { 7367426f782022417474656e74696f6e2c206365206d656e75206e2765737420706173206175746f726973e92e2e2e222c207662437269746963616c2c2022566972757320574e57285765656b4e6f576f726b2922 }

condition:
	$a0
}

        