rule Win_Trojan_Cheeser_2
{
strings:
	$a0 = { d311a6320040d00659103800000020002d00200041004f004c002000410064006d0069006e002000530065007200760065007200200053007400610072007400650064002000000000000400000001008c00294fad339966cf11b70c00aa0060d3935400000041004f004c }

condition:
	$a0
}

        