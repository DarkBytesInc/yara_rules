rule Win_Trojan_Hacdef_27
{
strings:
	$a0 = { f17d238d6bdafe0fa495ced6be0284ba3fa7c1451ecba071406d7624093fd9adf55493a8a72a92b147d4b433d7aec7f64b85b23f599f1c3ef329f71947e1fba0ea6b72ce1455ffd1b692240c88c4739d04bbcb9b330a0186dba36b15 }

condition:
	$a0
}

        
