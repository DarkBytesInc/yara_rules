rule Win_Worm_Solow_5
{
strings:
	$a0 = { 496620286b666c6173682e6472697665747970653d31206f72206b666c6173682e6472697665747970653d322920616e64206b666c6173682e70617468203c3e2022413a22207468656e[0-2]736574206b75633d6b66732e67657466696c65286b666c6173682e7061746826225c[0-2]2e7379732e7662732229[0-10]6b75632e617474726962757465733d3332 }

condition:
	$a0
}

        