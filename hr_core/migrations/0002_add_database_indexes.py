# Generated migration for adding database indexes to HR Core models
# Improves query performance for frequently accessed fields

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('hr_core', '0001_initial'),
    ]

    operations = [
        # Employee indexes
        migrations.AlterField(
            model_name='employee',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('active', 'Active'),
                    ('on_leave', 'On Leave'),
                    ('terminated', 'Terminated'),
                    ('suspended', 'Suspended'),
                ],
                default='active',
                db_index=True,
                help_text='Employment status'
            ),
        ),
        migrations.AlterField(
            model_name='employee',
            name='employment_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('full_time', 'Full Time'),
                    ('part_time', 'Part Time'),
                    ('contract', 'Contract'),
                    ('intern', 'Intern'),
                    ('freelance', 'Freelance'),
                ],
                default='full_time',
                db_index=True,
                help_text='Type of employment'
            ),
        ),
        migrations.AlterField(
            model_name='employee',
            name='department',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name='employees',
                to='hr_core.department',
                db_index=True,
                help_text='Department assignment'
            ),
        ),
        migrations.AlterField(
            model_name='employee',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the employee record was created'
            ),
        ),
        migrations.AlterField(
            model_name='employee',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When the employee record was last updated'
            ),
        ),

        # OnboardingChecklist indexes
        migrations.AlterField(
            model_name='onboardingchecklist',
            name='employment_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('full_time', 'Full Time'),
                    ('part_time', 'Part Time'),
                    ('contract', 'Contract'),
                    ('intern', 'Intern'),
                    ('freelance', 'Freelance'),
                ],
                db_index=True,
                help_text='Employment type for this checklist'
            ),
        ),
        migrations.AlterField(
            model_name='onboardingchecklist',
            name='department',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name='onboarding_checklists',
                to='hr_core.department',
                db_index=True,
                help_text='Department this checklist applies to'
            ),
        ),
        migrations.AlterField(
            model_name='onboardingchecklist',
            name='is_active',
            field=models.BooleanField(
                default=True,
                db_index=True,
                help_text='Whether this checklist is active'
            ),
        ),
        migrations.AlterField(
            model_name='onboardingchecklist',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the checklist was created'
            ),
        ),
        migrations.AlterField(
            model_name='onboardingchecklist',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When the checklist was last updated'
            ),
        ),

        # OnboardingTask indexes
        migrations.AlterField(
            model_name='onboardingtask',
            name='category',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('it', 'IT Setup'),
                    ('hr', 'HR Onboarding'),
                    ('compliance', 'Compliance'),
                    ('training', 'Training'),
                    ('other', 'Other'),
                ],
                default='other',
                db_index=True,
                help_text='Task category'
            ),
        ),

        # EmployeeOnboarding indexes
        migrations.AlterField(
            model_name='employeeonboarding',
            name='checklist',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                related_name='employee_onboardings',
                to='hr_core.onboardingchecklist',
                db_index=True,
                help_text='Onboarding checklist template'
            ),
        ),

        # OnboardingTaskProgress indexes
        migrations.AlterField(
            model_name='onboardingtaskprogress',
            name='onboarding',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='task_progress',
                to='hr_core.employeeonboarding',
                db_index=True,
                help_text='Parent onboarding record'
            ),
        ),
        migrations.AlterField(
            model_name='onboardingtaskprogress',
            name='task',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='progress_records',
                to='hr_core.onboardingtask',
                db_index=True,
                help_text='Task being tracked'
            ),
        ),
        migrations.AlterField(
            model_name='onboardingtaskprogress',
            name='is_completed',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='Whether the task has been completed'
            ),
        ),

        # EmployeeDocument indexes
        migrations.AlterField(
            model_name='employeedocument',
            name='employee',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='documents',
                to='hr_core.employee',
                db_index=True,
                help_text='Employee this document belongs to'
            ),
        ),
        migrations.AlterField(
            model_name='employeedocument',
            name='template',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name='documents',
                to='hr_core.documenttemplate',
                db_index=True,
                help_text='Template used for this document'
            ),
        ),
        migrations.AlterField(
            model_name='employeedocument',
            name='category',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('employment_contract', 'Employment Contract'),
                    ('tax_form', 'Tax Form'),
                    ('nda', 'NDA'),
                    ('other', 'Other'),
                ],
                default='other',
                db_index=True,
                help_text='Document category'
            ),
        ),
        migrations.AlterField(
            model_name='employeedocument',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('draft', 'Draft'),
                    ('pending_signature', 'Pending Signature'),
                    ('signed', 'Signed'),
                    ('archived', 'Archived'),
                ],
                default='draft',
                db_index=True,
                help_text='Document status'
            ),
        ),
        migrations.AlterField(
            model_name='employeedocument',
            name='uploader',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                related_name='uploaded_documents',
                to='accounts.useraccount',
                db_index=True,
                help_text='User who uploaded the document'
            ),
        ),
        migrations.AlterField(
            model_name='employeedocument',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the document was created'
            ),
        ),
        migrations.AlterField(
            model_name='employeedocument',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When the document was last updated'
            ),
        ),

        # Offboarding indexes
        migrations.AlterField(
            model_name='offboarding',
            name='employee',
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='offboarding',
                to='hr_core.employee',
                db_index=True,
                help_text='Employee being offboarded'
            ),
        ),
        migrations.AlterField(
            model_name='offboarding',
            name='separation_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('resignation', 'Resignation'),
                    ('termination', 'Termination'),
                    ('retirement', 'Retirement'),
                    ('layoff', 'Layoff'),
                ],
                db_index=True,
                help_text='Type of separation'
            ),
        ),
        migrations.AlterField(
            model_name='offboarding',
            name='processed_by',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name='processed_offboardings',
                to='accounts.useraccount',
                db_index=True,
                help_text='HR person processing offboarding'
            ),
        ),
        migrations.AlterField(
            model_name='offboarding',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When offboarding was initiated'
            ),
        ),
        migrations.AlterField(
            model_name='offboarding',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When offboarding was last updated'
            ),
        ),
        migrations.AlterField(
            model_name='offboarding',
            name='completed_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When offboarding was completed'
            ),
        ),

        # PerformanceReview indexes
        migrations.AlterField(
            model_name='performancereview',
            name='employee',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='performance_reviews',
                to='hr_core.employee',
                db_index=True,
                help_text='Employee being reviewed'
            ),
        ),
        migrations.AlterField(
            model_name='performancereview',
            name='reviewer',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name='performance_reviews_given',
                to='accounts.useraccount',
                db_index=True,
                help_text='Manager conducting the review'
            ),
        ),
        migrations.AlterField(
            model_name='performancereview',
            name='review_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('annual', 'Annual'),
                    ('mid_year', 'Mid Year'),
                    ('promotion', 'Promotion'),
                    ('performance_improvement', 'Performance Improvement'),
                    ('exit', 'Exit'),
                ],
                default='annual',
                db_index=True,
                help_text='Type of review'
            ),
        ),
        migrations.AlterField(
            model_name='performancereview',
            name='status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('draft', 'Draft'),
                    ('pending_review', 'Pending Review'),
                    ('completed', 'Completed'),
                    ('archived', 'Archived'),
                ],
                default='draft',
                db_index=True,
                help_text='Review status'
            ),
        ),
        migrations.AlterField(
            model_name='performancereview',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the review was created'
            ),
        ),
        migrations.AlterField(
            model_name='performancereview',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When the review was last updated'
            ),
        ),
        migrations.AlterField(
            model_name='performancereview',
            name='completed_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='When the review was completed'
            ),
        ),

        # EmployeeGoal indexes
        migrations.AlterField(
            model_name='employeegoal',
            name='employee',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='goals',
                to='hr_core.employee',
                db_index=True,
                help_text='Employee for this goal'
            ),
        ),
        migrations.AlterField(
            model_name='employeegoal',
            name='category',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('performance', 'Performance'),
                    ('development', 'Development'),
                    ('team', 'Team'),
                    ('personal', 'Personal'),
                ],
                default='performance',
                db_index=True,
                help_text='Goal category'
            ),
        ),
        migrations.AlterField(
            model_name='employeegoal',
            name='priority',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('low', 'Low'),
                    ('medium', 'Medium'),
                    ('high', 'High'),
                    ('critical', 'Critical'),
                ],
                db_index=True,
                help_text='Goal priority'
            ),
        ),
        migrations.AlterField(
            model_name='employeegoal',
            name='created_at',
            field=models.DateTimeField(
                auto_now_add=True,
                db_index=True,
                help_text='When the goal was created'
            ),
        ),
        migrations.AlterField(
            model_name='employeegoal',
            name='updated_at',
            field=models.DateTimeField(
                auto_now=True,
                db_index=True,
                help_text='When the goal was last updated'
            ),
        ),
    ]
