rule Win_Spyware_Banker_5608
{
strings:
	$a0 = { 1c9e49472c8be942efb4dba2bbb2f35b4bb80be1e5ecee9e0aee26180513e03059234b236b9f5e7cdf63a05eb0ae6db04c5ba234992446ab8372e0fc24eb43fdd9fc05f6673ffffaef9e5dcdc5d47d22f32e5beb231d33510b99c3ab1b0cb55d635347350cf9cdae77c1b42456b974ed420e1039b9bcec2b86a7a310eb78043b595a6bd699cc2b3778c696440de18f93b07c546be8a9 }

condition:
	$a0
}

        