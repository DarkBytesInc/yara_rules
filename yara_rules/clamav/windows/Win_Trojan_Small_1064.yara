rule Win_Trojan_Small_1064
{
strings:
	$a0 = { 6a006a015753ff5538ebc3fece750d56ff55286a0a57ff55084febb2486a00515057564fff5524ebd764a13000000085c0780c8b400c8b701cad8b5808eb098b40348b98b80000008b733c8b741e788d741e18ad91ad50ad03c392ad03c35087f2ad03c333d2c1c20332104080380075f58bfd391775138b04240fb700c1e002034424048b040303c3abaf833f0075e383042402e2cb }

condition:
	$a0
}

        