rule Win_Spyware_Banker_3114
{
strings:
	$a0 = { 5703d89266833e63cfbfada3e9eff352ae0aa5df59939ecee4d8d0154f3e32f6f92a83d095a450b567d6dd482c15572709a07a6e8de6832bb80f684fbe800eac55b120f0996db9839dc9faa0ecf413959c6eb9913a93253373cf37c1515bac2fc39c12eed79b74997b3fa4a8330f94315464bd0ada55bef1a0a445ed0140fc5f8ef82c14756a87acafbfdce9 }

condition:
	$a0
}

        