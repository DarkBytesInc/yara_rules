rule Win_Spyware_62886_1
{
strings:
	$a0 = { 5703d89266833e63cfbfada3e9eff352ae0aa5df59939ecee4d8d0154f3e32f6f92a83d095a450b567d6dd482c15572709a07a6e8de6832bb80f684fbe800eac55b120f0996db9839dc9faa0ecf413959c6eb9913a932535ec01adc2819d0145b5913dd575c38ec34ad092d6cd2a805ce42e9ea9d3ffa9ea14ec3fd07818f8568c790fe41e7dddbe0a604764 }

condition:
	$a0
}

        