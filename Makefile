test::
	pytest -v tests

build:: format
	uv build

publish:: build
	# Uncomment the following line to publish the package
	# uv publish 