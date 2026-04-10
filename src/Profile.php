<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonGLPI;
use Html;
use Profile as CoreProfile;
use Session;

class Profile extends CoreProfile
{
    public static function getAllRights(): array
    {
        return [
            [
                'itemtype' => Scan::class,
                'label'    => __('Nessus scans', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_scan',
                'rights'   => [READ, UPDATE, CREATE],
            ],
            [
                'itemtype' => Config::class,
                'label'    => __('Nessus configuration', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_config',
                'rights'   => [READ, UPDATE],
            ],
            [
                'itemtype' => Vulnerability::class,
                'label'    => __('Nessus vulnerabilities', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_vulnerability',
                'rights'   => [READ, UPDATE],
            ],
            [
                'itemtype' => Host::class,
                'label'    => __('Nessus host tickets', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_ticket',
                'rights'   => [READ, CREATE],
            ],
        ];
    }

    public static function ensureProfileRights(): void
    {
        global $DB;

        $rights = static::getAllRights();
        if ($rights === []) {
            return;
        }

        $fields = array_column($rights, 'field');
        $profiles = [];
        foreach ($DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_profiles',
        ]) as $row) {
            $profileId = (int) ($row['id'] ?? 0);
            if ($profileId > 0) {
                $profiles[] = $profileId;
            }
        }

        if ($profiles === []) {
            return;
        }

        $existing = [];
        foreach ($DB->request([
            'SELECT' => ['profiles_id', 'name'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => [
                'name' => $fields,
            ],
        ]) as $row) {
            $existing[(int) $row['profiles_id'] . '|' . (string) $row['name']] = true;
        }

        foreach ($profiles as $profileId) {
            foreach ($rights as $right) {
                $field = (string) $right['field'];
                $key = $profileId . '|' . $field;
                if (isset($existing[$key])) {
                    continue;
                }

                $DB->insert('glpi_profilerights', [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                    'rights'      => 0,
                ]);
            }
        }
    }

    public static function saveRightsForProfile(int $profileId, array $submittedRights): void
    {
        global $DB;

        if ($profileId <= 0) {
            return;
        }

        foreach (static::getAllRights() as $right) {
            $field = (string) $right['field'];
            $selected = isset($submittedRights[$field]) && is_array($submittedRights[$field])
                ? array_map('intval', $submittedRights[$field])
                : [];

            $mask = 0;
            foreach ($right['rights'] as $value) {
                $value = (int) $value;
                if (in_array($value, $selected, true)) {
                    $mask |= $value;
                }
            }

            $existing = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_profilerights',
                'WHERE'  => [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                ],
                'LIMIT' => 1,
            ])->current();

            if ($existing) {
                $DB->update('glpi_profilerights', [
                    'rights' => $mask,
                ], [
                    'id' => (int) $existing['id'],
                ]);
            } else {
                $DB->insert('glpi_profilerights', [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                    'rights'      => $mask,
                ]);
            }
        }
    }

    public static function getCurrentRightsForProfile(int $profileId): array
    {
        global $DB;

        $result = [];
        if ($profileId <= 0) {
            return $result;
        }

        $fields = array_column(static::getAllRights(), 'field');
        foreach ($DB->request([
            'SELECT' => ['name', 'rights'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => [
                'profiles_id' => $profileId,
                'name'        => $fields,
            ],
        ]) as $row) {
            $result[(string) $row['name']] = (int) ($row['rights'] ?? 0);
        }

        return $result;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string
    {
        if ($item instanceof CoreProfile) {
            return __('Nessus Conector', 'nessusglpi');
        }

        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
    {
        if (!$item instanceof CoreProfile) {
            return true;
        }

        $profileId = (int) $item->getID();
        $currentRights = static::getCurrentRightsForProfile($profileId);
        $canEdit = Session::haveRight('profile', UPDATE) > 0;

        echo "<div class='card card-body'>";
        echo '<h3>' . __('Plugin rights', 'nessusglpi') . '</h3>';
        echo '<form method="post" action="/plugins/nessusglpi/front/profile.rights.php">';
        echo Html::hidden('profiles_id', ['value' => $profileId]);
        echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
        echo '<table class="tab_cadre_fixehov">';
        echo '<tr><th>' . __('Right', 'nessusglpi') . '</th><th>READ</th><th>UPDATE</th><th>CREATE</th></tr>';

        foreach (static::getAllRights() as $right) {
            $field = (string) $right['field'];
            $mask = (int) ($currentRights[$field] ?? 0);
            echo '<tr>';
            echo '<td><strong>' . Html::cleanInputText((string) $right['label']) . '</strong><br><span style="color:#667085;"><code>' . Html::cleanInputText($field) . '</code></span></td>';

            foreach ([READ, UPDATE, CREATE] as $permission) {
                echo '<td style="text-align:center;">';
                if (in_array($permission, $right['rights'], true)) {
                    $checked = ($mask & $permission) === $permission;
                    echo '<input type="checkbox" name="plugin_nessusglpi_rights[' . Html::cleanInputText($field) . '][]" value="' . $permission . '"' . ($checked ? ' checked' : '') . ($canEdit ? '' : ' disabled') . '>';
                } else {
                    echo '&mdash;';
                }
                echo '</td>';
            }

            echo '</tr>';
        }

        echo '</table>';

        if ($canEdit) {
            echo '<div style="margin-top:12px;">';
            echo Html::submit(__('Save'), ['name' => 'save_nessusglpi_rights', 'class' => 'btn btn-primary']);
            echo '</div>';
        }

        echo '</form>';
        echo '</div>';

        return true;
    }
}
