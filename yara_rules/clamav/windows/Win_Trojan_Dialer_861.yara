rule Win_Trojan_Dialer_861
{
strings:
	$a0 = { 7b17e11cd03681494fc6e6e438426f6dabb7d6c2c5b65adb6aab456c15270c4d0252e55f3516ae8696da130fd520980c30e4bcdfdae724046dfbeefddefd5ebeefccde7bedb5f75efbffda6badbda376767377b77ab8588d7a46cbe6386eb0bc40b089a935dabf3939ae56edaadfcb73 }

condition:
	$a0
}

        
