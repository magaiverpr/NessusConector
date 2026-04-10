<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Profile;

include('../../../inc/includes.php');

Session::checkRight('profile', UPDATE);

$profileId = (int) ($_POST['profiles_id'] ?? 0);
if ($profileId <= 0) {
    Session::addMessageAfterRedirect(__('Profile not found.', 'nessusglpi'), true);
    Html::back();
}

Profile::saveRightsForProfile($profileId, (array) ($_POST['plugin_nessusglpi_rights'] ?? []));
Session::addMessageAfterRedirect(__('Plugin rights updated successfully.', 'nessusglpi'));
Html::redirect('/front/profile.form.php?id=' . $profileId);
