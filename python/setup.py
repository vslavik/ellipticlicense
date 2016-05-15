from distutils.core import setup, Extension

setup(
    name = 'ellipticlicense',
    version = '0.1.1',
    description = 'Elliptic curves based license generator',
    author = 'Vaclav Slavik',
    author_email = 'vaclav@slavik.io',
    url = 'https://github.com/vslavik/ellipticlicense',
    download_url = 'https://github.com/vslavik/ellipticlicense/archive/master.zip',
    keywords = ['licensing'],
    license = 'Apache Software License',
    classifiers = [
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Development Status :: 4 - Beta',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    ext_modules=[Extension('_ellipticlicense',
                           sources=['c_api/base32.c', 'c_api/elliptic_license.c'],
                           libraries=['crypto'],
                           extra_compile_args=['--std=c99'],
                 )],
    py_modules=['ellipticlicense'],
)