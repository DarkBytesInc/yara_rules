rule Win_Spyware_Banker_5691
{
strings:
	$a0 = { 8c0185082d0e0d9108e5a10db00d40bba106e07af4b588a169220b23014cadc3bac01288081e96c1c5051cec464f8bc4106dd15700425cd003b1441224381b53ae4a18502945135502c92095f3870a54c83c440774d3148df002b80341b41f7c6d8aeb269629a44fc08c642efc506bc068173861838af22448170be46f449b308da50b92a742f53a90b95ef4 }

condition:
	$a0
}

        