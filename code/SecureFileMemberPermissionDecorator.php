<?php
/**
 * Creates a member based permission system for files
 *
 * @package securefiles
 * @subpackage default
 * @author Hamish Campbell <hn.campbell@gmail.com>
 * @copyright copyright (c) 2010, Hamish Campbell 
 */
class SecureFileMemberPermissionDecorator extends DataExtension {
	
	public static $many_many = array(
		'MemberPermissions' => 'Member'
	);
	
	/**
	 * View permission check
	 * 
	 * @param Member $member
	 * @return boolean
	 */
	function canViewSecured(Member $member = null) {
		if($member) {
			return $this->owner->AllMemberPermissions()->byID($member->ID);
		} else {
			return false;
		}
	}
	
	/**
	 * Collate permissions for this and all parent folders.
	 * 
	 * @return DataObjectSet
	 */
	function AllMemberPermissions() {
		return Member::get()->filter('ID', $this->memberIds($this->owner));
	}
	
	function InheritedMemberPermissions() {
		return Member::get()->filter('ID', $this->memberIds($this->owner->Parent()));
	}
	
	private function memberIds($folder) {
		$ids = array();
		while ($folder->ID) {
			$ids = array_merge($ids, $folder->getManyManyComponents('MemberPermissions')->map('ID','ID')->toArray());
			$folder = $folder->Parent();
		}
		return $ids;
	}
	
	/**
	 * Adds member select fields to CMS
	 * 
 	 * @param FieldSet $fields
 	 * @return void
 	 */
	public function updateCMSFields(FieldList $fields) {
		
		// Only modify folder objects with parent nodes
		if(!($this->owner instanceof Folder) || !$this->owner->ID)
			return;
			
		// Only allow ADMIN and SECURE_FILE_SETTINGS members to edit these options
		if(!Permission::checkMember(Member::currentUser(), array('ADMIN', 'SECURE_FILE_SETTINGS')))
			return;
		
		// Update Security Tab
		$security = $fields->fieldByName('Security');
		if (!$security) {
			$security = ToggleCompositeField::create('Security', _t('SecureFiles.SECUREFILETABNAME', 'Security'), array())->setHeadingLevel(4);
		}
		
		// Update Security Tab
		
		$members = GridField::create('MemberPermissions', _t('SecureFiles.MEMBERACCESSTITLE', 'Member Access'), $this->owner->MemberPermissions(), GridFieldConfig_RelationEditor::create());
		$security->push($members);
			
		if($this->owner->InheritSecured()) {
			$permissionMembers = $this->owner->InheritedMemberPermissions();
			if($permissionMembers->Count()) {
				$fieldText = implode(", ", $permissionMembers->map('ID', 'Name'));
			} else {
				$fieldText = _t('SecureFiles.NONE', "(None)");
			}
			$InheritedMembersField = new ReadonlyField("InheritedMemberPermissionsText", _t('SecureFiles.MEMBERINHERITEDPERMS', 'Inherited Member Permissions'), $fieldText);
			$InheritedMembersField->addExtraClass('prependUnlock');
			$security->push($InheritedMembersField);
		}
	}
}
