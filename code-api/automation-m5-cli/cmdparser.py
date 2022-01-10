import click


@click.group()
def cli():
    pass


@click.command()
def hello():
    click.echo('Hello world')


cli.add_command(hello)
