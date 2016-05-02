class AddBadgeStatusToProjects < ActiveRecord::Migration
  def change
    add_column :projects, :badge_status, :string
    add_index :projects, :badge_status
  end

  def up
    Project.find_each do |project|
      project.update_badge_status
      project.save
    end
  end

  def down
    # Having projects.badge_status column remain is OK.
  end
end
