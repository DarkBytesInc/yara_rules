rule Win_Spyware_Banker_1931
{
strings:
	$a0 = { 6e5be9f2aad6a4f4c4de9c49f811cb56366a4a5087c20f2841eac56d3a7dd058e1395c392ba51cef955abcdac2f6664cd84e032cbd9c893d08bc5e7387c36687f29a1c858a16373edf96900c36bce154081f0bb79b72c711d523f3ae2e0b5d6ebf508935d2555f9b4ebd69fe04097020e92ade51470ad56876a5eb4b73068754963dc3b612f59ed068e9d30334fb6dbde250f3abe241 }

condition:
	$a0
}

        