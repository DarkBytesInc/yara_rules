rule Win_Trojan_Philis_26
{
strings:
	$a0 = { 555e353ace8e2f6be9f2731cf426419efdb314d54fdf75d94e1fd980d3146b7923a33668eafd6bc3a52bd83303450431670391bf9da9490fa911347ea418d5455bcb557d6ebf1f522c9a5519e1a105b17b128da4fe62ccade2a6a388b7a1fb11051ee7b2394f2a62b5c0bea1c6c5c4ef16ba5e4226258a6f7a924cd16993cea9c94e5fd4da3b1d412bbd215c41bd21ee1fd0dc684399 }

condition:
	$a0
}

        