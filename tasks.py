from pathlib import Path
from tempfile import NamedTemporaryFile

from invoke import Context, task
from passlib.hash import pbkdf2_sha512

ROOT = Path(__file__).parent.resolve()


@task
def build(ctx: Context):
    with ctx.cd(ROOT):
        ctx.run('rm -rf dist')
        ctx.run('poetry build --format sdist')
        ctx.run('poetry export --without-hashes -f requirements.txt -o dist/requirements.txt')


@task(pre=[build])
def local_docker(ctx: Context, tag='local'):
    with ctx.cd(ROOT):
        ctx.run(f'docker build -t ghcr.io/brewblox/brewblox-auth:{tag} .')


@task
def run(ctx: Context):
    with ctx.cd(ROOT):
        ctx.run('flask --app brewblox_auth run', pty=True)


def read_users(ctx: Context, fname: str) -> tuple[Path, dict]:
    if Path(fname).is_absolute():
        fpath = Path(fname)
    else:
        fpath = ROOT / fname

    fpath.parent.mkdir(exist_ok=True)

    if fpath.exists():
        content = ctx.run(f'sudo cat "{fpath}"', hide=True).stdout
    else:
        content = ''

    return (fpath, {
        name: hashed
        for (name, hashed)
        in [line.strip().split(':', 1)
            for line in content.split('\n')
            if ':' in line]
    })


@task
def add_user(ctx: Context,
             username: str,
             password: str,
             fname: str = 'data/users.passwd'):
    fpath, users = read_users(ctx, fname)
    users[username] = pbkdf2_sha512.hash(password)

    with NamedTemporaryFile('w') as tempf:
        for k, v in users.items():
            tempf.write(f'{k}:{v}\n')
        tempf.flush()
        ctx.run(f'sudo cp "{tempf.name}" "{fpath}"')
        ctx.run(f'sudo chown root:root "{fpath}"')
        ctx.run(f'sudo chmod a+r "{fpath}"')

    print('users:', ', '.join(users.keys()))


@task
def remove_user(ctx: Context,
                username: str,
                fname: str = 'data/users.passwd'):
    fpath, users = read_users(ctx, fname)

    try:
        del users[username]
        with NamedTemporaryFile('w') as tempf:
            for k, v in users.items():
                tempf.write(f'{k}:{v}\n')
            tempf.flush()
            ctx.run(f'sudo cp "{tempf.name}" "{fpath}"')
            ctx.run(f'sudo chown root:root "{fpath}"')
            ctx.run(f'sudo chmod a+r "{fpath}"')

    except KeyError:
        pass

    print('users:', ', '.join(users.keys()))
