rule Win_Spyware_Banker_6034
{
strings:
	$a0 = { 6dd00f7fac12136ab64468530a4e336f2800c904230700fbe3b7113378bb3e254135f29e14c22ae39b24627b0f856d882044f35a24c13476ddc40fb284953f6aefb12b82edc83bd9fd6d023a974457af460514a9b3768d2e787e4eec1977cdebf82272cb1694db1e969ba2cedff894826433fdcb90928dfee2c261a36d8a6a35f892186c2e97bde34af6f685 }

condition:
	$a0
}

        