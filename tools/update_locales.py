from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
TARGET_DIRS = ['src', 'front', 'ajax', 'templates', 'hook.php', 'setup.php']
LOCALES_DIR = ROOT / 'locales'
DOMAIN = 'nessusglpi'
PATTERNS = [
    re.compile(r"__\(\s*'((?:\\.|[^'])*)'", re.DOTALL),
    re.compile(r'__\(\s*"((?:\\.|[^\"])*)"', re.DOTALL),
]


def unescape(value: str) -> str:
    return bytes(value, 'utf-8').decode('unicode_escape')


def escape_po(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def collect_files():
    files = []
    for target in TARGET_DIRS:
        path = ROOT / target
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob('*') if p.is_file() and p.suffix in {'.php', '.twig'}))
        elif path.is_file():
            files.append(path)
    return files


def collect_messages():
    messages = {}
    for path in collect_files():
        content = path.read_text(encoding='utf-8')
        rel = path.relative_to(ROOT).as_posix()
        for pattern in PATTERNS:
            for match in pattern.finditer(content):
                msgid = unescape(match.group(1))
                lineno = content.count('\n', 0, match.start()) + 1
                messages.setdefault(msgid, []).append(f'{rel}:{lineno}')
    return dict(sorted(messages.items(), key=lambda item: item[0].lower()))


def render_catalog(messages, language, translator, translations=None):
    translations = translations or {}
    lines = [
        'msgid ""',
        'msgstr ""',
        '"Project-Id-Version: Nessus Conector\\n"',
        f'"Language: {language}\\n"',
        f'"Language-Team: {translator}\\n"',
        '"MIME-Version: 1.0\\n"',
        '"Content-Type: text/plain; charset=UTF-8\\n"',
        '"Content-Transfer-Encoding: 8bit\\n"',
        '"Plural-Forms: nplurals=2; plural=(n != 1);\\n"',
        '',
    ]

    for msgid, refs in messages.items():
        for ref in refs:
            lines.append(f'#: {ref}')
        lines.append(f'msgid "{escape_po(msgid)}"')
        translated = translations.get(msgid, '')
        lines.append(f'msgstr "{escape_po(translated)}"')
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def main():
    LOCALES_DIR.mkdir(exist_ok=True)
    messages = collect_messages()

    pt_br = {
        'Nessus Conector': 'Nessus Conector',
        'Scans': 'Scans',
        'Configuration': 'Configuracao',
        'Vulnerabilities': 'Vulnerabilidades',
        'Scan history': 'Historico de scans',
        'Imported host': 'Host importado',
        'Imported hosts': 'Hosts importados',
        'Nessus scan': 'Scan do Nessus',
        'Nessus scan run': 'Execucao de scan do Nessus',
        'Latest synchronization': 'Ultima sincronizacao',
        'Create ticket': 'Criar chamado',
        'Open new ticket': 'Abrir novo chamado',
        'Show details': 'Mostrar detalhes',
        'Open in Nessus': 'Abrir no Nessus',
        'Delete selected': 'Excluir selecionados',
        'View vulnerabilities': 'Ver vulnerabilidades',
        'Scan executed at': 'Scan executado em',
        'Last synchronization': 'Ultima sincronizacao',
        'Status': 'Status',
        'Actions': 'Acoes',
        'Host': 'Host',
        'Ticket': 'Chamado',
        'Severity': 'Severidade',
        'Name': 'Nome',
        'Solution': 'Solucao',
        'Description': 'Descricao',
        'Overview': 'Visao geral',
        'Outputs': 'Saidas',
    }

    fr_fr = {
        'Nessus Conector': 'Nessus Conector',
        'Scans': 'Scans',
        'Configuration': 'Configuration',
        'Vulnerabilities': 'Vulnerabilites',
        'Scan history': 'Historique des scans',
        'Imported host': 'Hote importe',
        'Imported hosts': 'Hotes importes',
        'Nessus scan': 'Scan Nessus',
        'Nessus scan run': 'Execution du scan Nessus',
        'Latest synchronization': 'Derniere synchronisation',
        'Create ticket': 'Creer un ticket',
        'Open new ticket': 'Ouvrir un nouveau ticket',
        'Show details': 'Afficher les details',
        'Open in Nessus': 'Ouvrir dans Nessus',
        'Delete selected': 'Supprimer la selection',
        'View vulnerabilities': 'Voir les vulnerabilites',
        'Scan executed at': 'Scan execute le',
        'Last synchronization': 'Derniere synchronisation',
        'Status': 'Statut',
        'Actions': 'Actions',
        'Host': 'Hote',
        'Ticket': 'Ticket',
        'Severity': 'Severite',
        'Name': 'Nom',
        'Solution': 'Correctif',
        'Description': 'Description',
        'Overview': 'Vue d ensemble',
        'Outputs': 'Sorties',
    }

    pot = render_catalog(messages, 'en_GB', 'English (United Kingdom)', {msgid: '' for msgid in messages})
    en = render_catalog(messages, 'en_GB', 'English (United Kingdom)', {msgid: msgid for msgid in messages})
    pt = render_catalog(messages, 'pt_BR', 'Portugues (Brasil)', pt_br)
    fr = render_catalog(messages, 'fr_FR', 'Francais (France)', fr_fr)

    (LOCALES_DIR / f'{DOMAIN}.pot').write_text(pot, encoding='utf-8')
    (LOCALES_DIR / 'en_GB.po').write_text(en, encoding='utf-8')
    (LOCALES_DIR / 'pt_BR.po').write_text(pt, encoding='utf-8')
    (LOCALES_DIR / 'fr_FR.po').write_text(fr, encoding='utf-8')


if __name__ == '__main__':
    main()
