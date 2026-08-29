#!/bin/sh
# Stands in for the real `steampipe` CLI in tests. Routes on a substring
# of the SQL text to return table-shaped fixtures instead of hitting a
# real AWS account/cluster.
#
# IMPORTANT: every fixture below is wrapped in steampipe's real
# {"columns": [...], "rows": [...]} envelope -- an earlier version of
# this file used a bare JSON array, which matched what
# internal/steampipe/client.go *assumed* the real CLI would emit rather
# than what it actually emits. That mismatch meant every ingest-package
# test was passing against a fixture shape that didn't match reality,
# right up until a real cluster's `authz-graph ingest-k8s` run hit the
# real envelope and failed to decode. Confirmed against real
# `steampipe query ... --output json` output before fixing this file --
# don't revert this wrapping without re-confirming against a real
# install.
sql="$2"
case "$sql" in
  *aws_iam_user*)
    # NOTE: aws_iam_user.groups is NOT a list of group-name strings --
    # it's the full AWS API Group object per membership (Arn,
    # CreateDate, GroupId, GroupName, Path), unlike
    # attached_policy_arns which the plugin *does* flatten to a
    # []string of ARNs. Confirmed against a real cluster/account
    # query; don't collapse this back to bare strings.
    #
    # NOTE: inline_policies_std is a list of {PolicyName,
    # PolicyDocument: {Statement: [...]}} -- there is no separate
    # "aws_iam_user_policy" table. alice has an inline policy here
    # (distinct from her attached-via-group S3ReadOnly access) so the
    # inline-policy grant path is exercised independently.
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"arn","data_type":"text"},{"name":"attached_policy_arns","data_type":"jsonb"},{"name":"groups","data_type":"jsonb"},{"name":"inline_policies_std","data_type":"jsonb"}],
 "rows":[{"name":"alice","arn":"arn:aws:iam::111111111111:user/alice","attached_policy_arns":[],"groups":[{"Arn":"arn:aws:iam::111111111111:group/engineers","CreateDate":"2024-01-01T00:00:00Z","GroupId":"AGPAEXAMPLE","GroupName":"engineers","Path":"/"}],"inline_policies_std":[{"PolicyName":"SelfManageAccessKeys","PolicyDocument":{"Statement":[{"Sid":"AllowOwnKeys","Effect":"Allow","Action":["iam:CreateAccessKey","iam:DeleteAccessKey"],"Resource":["arn:aws:iam::111111111111:user/alice"]}]}}]}]}
JSON
    ;;
  *aws_iam_group*)
    # Mirror of the above: users is a list of full AWS API User
    # objects, not bare name strings.
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"arn","data_type":"text"},{"name":"attached_policy_arns","data_type":"jsonb"},{"name":"users","data_type":"jsonb"},{"name":"inline_policies_std","data_type":"jsonb"}],
 "rows":[{"name":"engineers","arn":"arn:aws:iam::111111111111:group/engineers","attached_policy_arns":["arn:aws:iam::111111111111:policy/S3ReadOnly"],"users":[{"Arn":"arn:aws:iam::111111111111:user/alice","CreateDate":"2024-01-01T00:00:00Z","UserId":"AIDAEXAMPLE","UserName":"alice","Path":"/"}],"inline_policies_std":[]}]}
JSON
    ;;
  *aws_iam_role*)
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"arn","data_type":"text"},{"name":"attached_policy_arns","data_type":"jsonb"},{"name":"inline_policies_std","data_type":"jsonb"},{"name":"assume_role_policy_std","data_type":"jsonb"}],
 "rows":[{"name":"deploy-role","arn":"arn:aws:iam::111111111111:role/deploy-role","attached_policy_arns":["arn:aws:iam::111111111111:policy/DeployPolicy"],"inline_policies_std":[],"assume_role_policy_std":{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111111111111:group/engineers"]},"Action":"sts:AssumeRole"}]}}]}
JSON
    ;;
  *aws_iam_policy*)
    # NOTE: there is no "aws_iam_policy_statement" table in the real
    # Steampipe AWS plugin -- statements come from aws_iam_policy's
    # policy_std column (the plugin's normalized policy-document form:
    # Action/Resource always arrays), flattened client-side in
    # internal/ingest/aws_iam.go. Confirmed against a real account;
    # don't reintroduce the nonexistent per-statement table here.
    cat <<'JSON'
{"columns":[{"name":"arn","data_type":"text"},{"name":"policy_std","data_type":"jsonb"}],
 "rows":[
  {"arn":"arn:aws:iam::111111111111:policy/S3ReadOnly","policy_std":{"Statement":[{"Sid":"AllowRead","Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::prod-data-bucket","arn:aws:s3:::prod-data-bucket/*"]}]}},
  {"arn":"arn:aws:iam::111111111111:policy/DeployPolicy","policy_std":{"Statement":[{"Sid":"AllowDeploy","Effect":"Allow","Action":["s3:PutObject","cloudformation:*"],"Resource":["arn:aws:s3:::prod-data-bucket/*","*"]}]}}
 ]}
JSON
    ;;
  *kubernetes_service_account*)
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"namespace","data_type":"text"}],
 "rows":[{"name":"web-app","namespace":"prod"}]}
JSON
    ;;
  *kubernetes_role_binding*)
    # NOTE: the real kubernetes_role_binding table has no "role_ref"
    # column -- RoleRef is flattened into role_name/role_api_group/
    # role_kind scalar columns. See table_kubernetes_role_binding.go
    # in github.com/turbot/steampipe-plugin-kubernetes; don't
    # reintroduce a bundled role_ref column here.
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"namespace","data_type":"text"},{"name":"role_name","data_type":"text"},{"name":"role_api_group","data_type":"text"},{"name":"role_kind","data_type":"text"},{"name":"subjects","data_type":"jsonb"}],
 "rows":[{"name":"pod-reader-binding","namespace":"prod","role_name":"pod-reader","role_api_group":"rbac.authorization.k8s.io","role_kind":"Role","subjects":[{"kind":"ServiceAccount","name":"web-app","namespace":"prod"}]}]}
JSON
    ;;
  *kubernetes_role*)
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"namespace","data_type":"text"},{"name":"rules","data_type":"jsonb"}],
 "rows":[{"name":"pod-reader","namespace":"prod","rules":[{"api_groups":[""],"resources":["pods"],"verbs":["get","list","watch"]}]}]}
JSON
    ;;
  *kubernetes_cluster_role_binding*)
    # Reproduces two real-world shapes seen against a live EKS cluster:
    # 1) a ClusterRoleBinding referencing a ServiceAccount (here, the
    #    stock kube-system "bootstrap-signer") that
    #    kubernetes_service_account never returns -- e.g. because the
    #    ingest credential can list bindings cluster-wide but lacks
    #    `list` on ServiceAccounts in kube-system. Exercises the
    #    ServiceAccount auto-vivify path rather than crashing AddEdge.
    # 2) a ClusterRoleBinding referencing a built-in EKS User subject
    #    (here, "eks:fargate-scheduler", mirroring a real cluster) --
    #    User/Group subjects never have a backing k8s object at all, so
    #    this exercises the User/Group auto-vivify path that makes
    #    `why`/`effective` queryable for these instead of failing with
    #    "unknown principal".
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"role_name","data_type":"text"},{"name":"role_api_group","data_type":"text"},{"name":"role_kind","data_type":"text"},{"name":"subjects","data_type":"jsonb"}],
 "rows":[
  {"name":"system:controller:bootstrap-signer","role_name":"system:controller:bootstrap-signer","role_api_group":"rbac.authorization.k8s.io","role_kind":"ClusterRole","subjects":[{"kind":"ServiceAccount","name":"bootstrap-signer","namespace":"kube-system"}]},
  {"name":"eks:fargate-scheduler","role_name":"eks:fargate-scheduler","role_api_group":"rbac.authorization.k8s.io","role_kind":"ClusterRole","subjects":[{"kind":"User","name":"eks:fargate-scheduler"}]}
 ]}
JSON
    ;;
  *kubernetes_cluster_role*)
    cat <<'JSON'
{"columns":[{"name":"name","data_type":"text"},{"name":"rules","data_type":"jsonb"}],
 "rows":[
  {"name":"system:controller:bootstrap-signer","rules":[{"api_groups":[""],"resources":["configmaps"],"verbs":["get","update"]}]},
  {"name":"eks:fargate-scheduler","rules":[{"api_groups":[""],"resources":["pods"],"verbs":["get","update","patch"]}]}
 ]}
JSON
    ;;
  *)
    echo '{"columns":[],"rows":[]}'
    ;;
esac
