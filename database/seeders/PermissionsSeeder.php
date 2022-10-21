<?php

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class PermissionsSeeder extends Seeder
{
    private $data = [];

    public function run()
    {
        $this->loadData();
        $this->seedRoles();
    }

    public function loadData(): void
    {
        $this->data = require_once database_path("data/permissions_roles.php");
    }

    private function seedRoles(): void
    {
        Role::create(['name' => 'super-admin', 'guard_name' => 'api']);

        foreach ($this->data as $roleName => $perms) {
            $role = Role::create(['name' => $roleName, 'guard_name' => 'api']);
            $this->seedRolePermissions($role, $perms);
        }
    }

    private function seedRolePermissions(Role $role, array $modelPermissions): void
    {
        foreach ($modelPermissions as $model => $perms) {
            $buildedPerms = collect($perms)
                ->crossJoin($model)
                ->map(function ($item) {
                    $perm = implode('-', $item); //view-post
                    Permission::findOrCreate($perm, 'api');

                    return $perm;
                })->toArray();

            $role->givePermissionTo($buildedPerms);
        }
    }
}
