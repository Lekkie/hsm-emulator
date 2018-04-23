HSM Simulator is a simple HSM simulator providing a number of commands compatible
with a Thales 8000/9000 HSM. It is based on the work done by [hsmsim](http://github.com/leachbj/hsmsim) and I extended to support a couple more commands. 
The simulator only supports a small number of commands and can only use test LMKs so should not be considered a replacement for a real HSM however it may be useful during a development of software
that interacts with a HSM.



## Quick start

The simulator runs as a java process

  java -jar hsmsim.jar

Alternatively the simulator can be deployed as a web application, deploy the hsmsim-war.war to a suitable
servlet container.

## Contributing

The simulator supports a very small number of commands and only supports the test LMKs.  Contributions of
additional command support welcomed.

## License
Copyright 2013 Bernard Leach

Licensed under the MIT license [http://opensource.org/licenses/MIT]
