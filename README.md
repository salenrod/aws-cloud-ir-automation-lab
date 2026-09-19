# AWS Cloud Incident Response Automation Lab

Laboratório de resposta a incidentes em AWS que transforma triagem e contenção de uma instância EC2 em código. O projeto usa Terraform, AWS Lambda, Python e PowerShell para validar um fluxo controlado, auditável e idempotente, baseado em um finding sintético do Amazon GuardDuty.

> Status atual: fundação segura, triagem, contenção controlada, orquestração com AWS Step Functions, ingestão sintética por Amazon EventBridge e observabilidade operacional com CloudWatch, SNS e KMS validadas em AWS. A preservação de evidência S3 antes da contenção está implementada e aguarda a validação controlada após o próximo deploy.

## Objetivos

Este projeto foi construído para demonstrar competências práticas esperadas em uma operação de Cloud Security e SecOps:

- analisar e enriquecer findings de segurança em ambientes AWS;
- transformar playbooks manuais em automações Python;
- aplicar contenção de EC2 com controles fail-closed;
- orquestrar decisões de resposta com AWS Step Functions;
- receber eventos de segurança por um barramento EventBridge isolado;
- encaminhar somente eventos compatíveis com uma regra fail-closed;
- monitorar ingestão, orquestração, triagem, contenção e DLQ com CloudWatch;
- alertar falhas operacionais por um tópico SNS criptografado com chave KMS do projeto;
- implementar privilégio mínimo com IAM;
- preservar estado e idempotência com DynamoDB;
- preservar evidência normalizada e versionada no S3 antes de qualquer mutação da EC2;
- verificar integridade com checksum SHA-256 do S3 e hash recalculado após leitura;
- registrar evidências operacionais em CloudWatch Logs;
- notificar a operação por SNS;
- provisionar e validar a infraestrutura com Terraform;
- produzir testes, runbooks e documentação post-mortem.

## Cenário de incidente

O laboratório utiliza um evento no formato do Amazon EventBridge que representa um finding de criptomineração em EC2:

```text
CryptoCurrency:EC2/BitcoinTool.B!DNS
```

A triagem associa esse comportamento à técnica [MITRE ATT&CK T1496.001 — Compute Hijacking](https://attack.mitre.org/techniques/T1496/001/), da tática **Impact**.

O finding é sintético. O projeto não depende de atividade maliciosa real e não habilita um detector GuardDuty. Para manter o teste isolado, o evento é publicado em um barramento EventBridge customizado com uma origem exclusiva do laboratório.

## Arquitetura

```mermaid
flowchart TD
    A["Finding sintético"] --> B["EventBridge isolado"]
    B --> C["Step Functions"]
    C --> D["Lambda de triagem"]
    D --> E{"Contenção elegível?"}
    E -->|Sim| F["Lambda de contenção"]
    E -->|Não| G["Finalizar sem alteração"]
    F --> H["Evidência S3 versionada"]
    H --> K["DynamoDB e quarentena EC2"]
    K --> L["SNS e logs"]
    B --> I["CloudWatch dashboard e alarmes"]
    C --> I
    D --> I
    F --> I
    I --> J["SNS criptografado com KMS"]
```

Uma regra EventBridge aceita somente a origem sintética, o detail type de finding e recursos EC2 Instance. O destino é o workflow Standard, que invoca a triagem e usa uma decisão explícita para encaminhar somente findings elegíveis à contenção. Entregas que não alcançam o destino usam política curta de retry e uma SQS DLQ. No caminho elegível, a Lambda cria e verifica uma evidência S3 antes de alterar a EC2; qualquer falha de gravação, leitura, versão ou checksum interrompe a contenção.

O `Test-EventBridge.ps1` valida por padrão o caminho orientado a evento com severidade abaixo do limite, sem executar contenção. O `Test-Orchestration.ps1` também valida o caminho seguro diretamente e exige o parâmetro explícito `-ExecuteContainment` para o caminho elegível. Nesse modo autorizado, o script coleta evidências e restaura automaticamente o alvo no bloco `finally`. A contenção possui validação ponta a ponta independente por `Test-Containment.ps1`.

O dashboard do CloudWatch consolida métricas do EventBridge, SQS, Step Functions e Lambda. Seis alarmes monitoram falhas de entrega, backlog da DLQ, falhas e timeouts do workflow e erros das Lambdas. Todos encaminham o estado `ALARM` para o tópico SNS de incidentes, criptografado por uma chave KMS gerenciada pelo projeto.

## Componentes

| Componente | Responsabilidade |
| --- | --- |
| VPC e subnet isolada | Hospedam o alvo sem Internet Gateway, NAT Gateway ou rota padrão para a internet |
| Security group baseline | Estado normal do alvo; sem regras de entrada |
| Security group de quarentena | Bloqueia todo o tráfego durante a contenção |
| EC2 descartável | Alvo autorizado, sem IP público, com IMDSv2 obrigatório e volume raiz criptografado |
| Lambda de triagem | Normaliza o finding, consulta EC2, aplica guardrails e mapeia MITRE ATT&CK |
| Lambda de contenção | Revalida o alvo, preserva e verifica a evidência, troca o security group, altera a tag e confirma a mutação |
| EventBridge | Recebe findings sintéticos em um barramento isolado e encaminha somente eventos compatíveis |
| SQS DLQ | Preserva eventos cuja entrega ao workflow falha após as tentativas configuradas |
| Step Functions | Orquestra triagem, decisão e contenção por um workflow Standard auditável |
| DynamoDB | Mantém o ledger do incidente, lease de processamento, idempotência e TTL |
| SNS | Envia notificações de contenção e alarmes operacionais por um tópico criptografado |
| KMS | Protege o tópico SNS com chave gerenciada pelo projeto e rotação automática |
| CloudWatch Logs | Armazena logs estruturados das Lambdas com retenção limitada |
| CloudWatch dashboard | Consolida métricas de ingestão, workflow, Lambdas, duração e DLQ |
| CloudWatch alarms | Detecta falhas operacionais e encaminha alertas ao tópico SNS |
| S3 de evidências | Guarda o JSON pré-contenção com criação condicional, versionamento, criptografia e checksum SHA-256 |
| Terraform | Provisiona, atualiza e verifica drift da infraestrutura |

## Controles de segurança

A contenção só pode ocorrer quando todas as condições abaixo são satisfeitas:

- severidade igual ou superior ao limite configurado;
- recurso afetado do tipo EC2 Instance;
- instância em estado suportado;
- instância igual ao alvo explicitamente permitido;
- tag `AutoContainment=true`;
- tag `DataClassification=synthetic`;
- tag inicial `IncidentStatus=clean`;
- exatamente uma interface de rede;
- somente o security group baseline associado;
- security group de quarentena sem nenhuma regra.

A Lambda de contenção consulta novamente a EC2 imediatamente antes da mutação. Ela não confia somente no snapshot produzido pela triagem.

Depois de adquirir o lease do incidente, a função serializa um JSON canônico com finding normalizado, decisão, mapeamento MITRE e estado ao vivo da instância. O objeto é criado em `incidents/<incident-id>/pre-containment.json` com `If-None-Match: *`, checksum SHA-256 e criptografia `AES256`. A mesma versão é lida de volta; o checksum informado pelo S3 e o hash dos bytes baixados precisam coincidir antes de `ec2:ModifyInstanceAttribute`.

As permissões de alteração são limitadas à instância descartável e ao security group de quarentena gerenciados pelo Terraform. Os recursos reais não são codificados diretamente no repositório.

O acesso S3 da Lambda é limitado a `GetObject`, `GetObjectVersion` e `PutObject` sob o prefixo `incidents/*` do bucket de evidências. Ela não recebe permissão para listar, excluir ou alterar a configuração do bucket.

O tópico SNS usa uma chave KMS própria, com rotação automática. A política da chave permite o uso pelo CloudWatch somente para alarmes do laboratório na conta atual. A Lambda de contenção recebe apenas as permissões KMS necessárias para publicar no tópico criptografado.

## Idempotência e estado do incidente

A tabela DynamoDB utiliza `incident_id` como chave e registra, entre outros campos:

- `processing`, `contained` ou `failed`;
- identificador da instância;
- tipo e severidade do finding;
- técnica MITRE;
- security groups antes e depois da contenção;
- bucket, chave, checksum SHA-256 e version ID da evidência pré-contenção;
- timestamps de criação, atualização e conclusão;
- lease temporário de processamento;
- TTL para expiração dos dados do laboratório.

Uma repetição do mesmo incidente concluído retorna `already_contained`, não modifica novamente a EC2, não repete a notificação nem cria outra evidência e preserva o horário original da conclusão. Uma repetição de um incidente `failed` reutiliza somente a versão já registrada no ledger e exige que sua integridade seja confirmada.

## Estrutura do repositório

```text
aws-cloud-ir-automation-lab/
├── docs/
│   ├── containment-validation.md
│   ├── eventbridge-validation.md
│   ├── foundation-validation.md
│   ├── observability-validation.md
│   ├── orchestration-validation.md
│   └── triage-validation.md
├── events/
│   └── guardduty-crypto-ec2.json
├── infra/
│   ├── compute.tf
│   ├── containment.tf
│   ├── eventbridge.tf
│   ├── network.tf
│   ├── notifications-kms.tf
│   ├── observability.tf
│   ├── orchestration.tf
│   ├── outputs.tf
│   ├── providers.tf
│   ├── storage.tf
│   ├── terraform.tfvars.example
│   ├── triage.tf
│   ├── variables.tf
│   └── versions.tf
├── scripts/
│   ├── Test-Containment.ps1
│   ├── Test-EventBridge.ps1
│   ├── Test-Foundation.ps1
│   ├── Test-Observability.ps1
│   ├── Test-Orchestration.ps1
│   └── Test-Triage.ps1
├── src/
│   ├── containment/
│   │   ├── __init__.py
│   │   └── handler.py
│   └── triage/
│       ├── __init__.py
│       └── handler.py
├── tests/
│   ├── test_containment.py
│   └── test_triage.py
├── .gitignore
└── README.md
```

Arquivos `.tfstate`, `.tfvars`, pacotes ZIP de Lambda, planos salvos, caches e ambientes virtuais não devem ser versionados.

## Pré-requisitos

- Windows com PowerShell;
- AWS CLI v2 com suporte a `aws login`;
- Terraform CLI;
- Python e `venv`;
- conta AWS de laboratório;
- perfil `cloud-ir-signin` autenticado pelo navegador;
- perfil `cloud-ir-lab` configurado para exportar credenciais temporárias do perfil de login.

Exemplo conceitual da configuração local:

```ini
[profile cloud-ir-signin]
login_session = <identidade-autorizada>
region = us-east-1

[profile cloud-ir-lab]
credential_process = aws configure export-credentials --profile cloud-ir-signin --format process
region = us-east-1
```

Não armazene access keys no repositório.

## Autenticação para AWS CLI e Terraform

As credenciais de `aws login` são temporárias. Ao iniciar uma nova sessão de trabalho, autentique o perfil de entrada:

```powershell
aws login `
  --profile cloud-ir-signin `
  --region us-east-1
```

Selecione o perfil operacional para todos os SDKs executados no terminal, inclusive o AWS Provider do Terraform:

```powershell
$env:AWS_PROFILE = "cloud-ir-lab"
$env:AWS_REGION = "us-east-1"
$env:AWS_DEFAULT_REGION = "us-east-1"
$env:AWS_EC2_METADATA_DISABLED = "true"
```

Valide tanto o perfil explícito quanto a cadeia de credenciais que o Terraform utilizará:

```powershell
aws sts get-caller-identity --profile cloud-ir-lab
aws sts get-caller-identity
```

Os dois comandos devem retornar a mesma conta e identidade. Se o primeiro funcionar e o segundo falhar, `AWS_PROFILE` não foi definido corretamente na sessão atual.

As variáveis definidas com `$env:` permanecem somente no processo atual do PowerShell. Elas precisam ser configuradas novamente quando um novo terminal for aberto.

## Preparação local

Crie e ative o ambiente virtual:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Instale as dependências usadas nos testes locais:

```powershell
python -m pip install --upgrade pip
python -m pip install boto3 pytest
```

Crie o arquivo local de variáveis:

```powershell
Copy-Item `
  ".\infra\terraform.tfvars.example" `
  ".\infra\terraform.tfvars"
```

Revise `infra/terraform.tfvars` e informe somente os valores do ambiente, como o endereço de notificação. Esse arquivo não deve ser commitado.

## Provisionamento

Inicialize e valide:

```powershell
terraform -chdir=".\infra" init
terraform -chdir=".\infra" fmt -recursive -check
terraform -chdir=".\infra" validate
```

Gere um plano revisável:

```powershell
terraform -chdir=".\infra" plan `
  -parallelism=1 `
  -out="cloud-ir-lab.tfplan"
```

Planos Terraform podem conter dados sensíveis. Não os envie ao Git.

Depois de revisar criação, alteração e destruição:

```powershell
terraform -chdir=".\infra" apply `
  ".\cloud-ir-lab.tfplan"
```

Confirme a assinatura recebida por e-mail para que o SNS possa entregar notificações.

## Testes

### Testes unitários

```powershell
python -m pytest ".\tests" -q
```

Resultado registrado antes da ampliação da evidência:

```text
13 passed
```

A suíte de contenção ampliada possui 12 testes e passou localmente. Depois de substituir os arquivos, execute a suíte completa; com os cinco testes de triagem existentes, o total esperado é `17 passed`.

### Fundação

```powershell
.\scripts\Test-Foundation.ps1
```

Resultado registrado:

```text
Passed: 26
Failed: 0
```

### Triagem

```powershell
.\scripts\Test-Triage.ps1
```

Resultado registrado:

```text
Passed: 27
Failed: 0
```

### Contenção controlada

Este teste altera o security group e a tag da instância descartável. Revise o script antes de executá-lo:

```powershell
.\scripts\Test-Containment.ps1 `
  -ExecuteContainment
```

Resultado AWS registrado antes da preservação S3:

```text
Passed: 54
Failed: 0
```

O teste atualizado valida a primeira contenção, baixa a versão exata da evidência, recalcula o SHA-256, compara o checksum devolvido pelo S3 e confirma a referência no DynamoDB. Depois repete o mesmo incidente para comprovar que a mutação, a notificação e a evidência não são duplicadas. O novo resumo esperado, após o deploy, é `Passed: 66` e `Failed: 0`. Ao final, o alvo permanece intencionalmente em quarentena.

### Orquestração

Este teste inicia um workflow Standard com severidade abaixo do limite de triagem. Ele valida a decisão sem executar a contenção nem modificar a instância:

```powershell
.\scripts\Test-Orchestration.ps1
```

Resultado registrado:

```text
Passed: 23
Failed: 0
```

O histórico confirmou `TriageFinding=entered` e `ContainTarget=not-entered`. Ao final, a instância permaneceu com `IncidentStatus=clean` e com o security group baseline.

O caminho elegível é executado somente com autorização explícita:

```powershell
.\scripts\Test-Orchestration.ps1 `
  -ExecuteContainment
```

Resultado AWS registrado antes da preservação S3:

```text
Passed: 40
Failed: 0
```

O teste atualizado acrescenta a validação da evidência S3 e deve terminar com `Passed: 50` e `Failed: 0` depois do deploy. O caminho seguro continua com `23/23` porque não chama a contenção.

Essa execução apresentou:

```text
Workflow:           SUCCEEDED
Resultado:          contained
Recurso alterado:   true
Idempotente:        false
Notificação:        published
Histórico:          TriageFinding -> EvaluateContainmentEligibility -> ContainTarget
DynamoDB:           status=contained, referência S3, lease ausente e TTL presente
S3:                 versão exata, AES256 e SHA-256 confirmados
CloudWatch Logs:    event=containment_complete
```

O script armazena temporariamente o evento, a descrição e o histórico da execução, o item do DynamoDB, a versão baixada da evidência S3, a resposta bruta da consulta ao CloudWatch, o evento de conclusão correlacionado e o estado de recuperação. Esses artefatos permanecem fora do Git porque contêm identificadores específicos da conta.

Após a coleta, o bloco `finally` restaura o security group baseline e `IncidentStatus=clean`. A regressão final confirmou a recuperação, `26/26` verificações da fundação e ausência de drift no Terraform.

### Ingestão orientada a evento

Este teste publica um único finding sintético de baixa severidade no barramento customizado. A regra encaminha o evento ao workflow, mas a triagem segue o caminho seguro e não executa a contenção:

```powershell
.\scripts\Test-EventBridge.ps1
```

Resultado registrado:

```text
Passed: 37
Failed: 0
```

A validação confirmou que:

- o evento EC2 compatível corresponde ao event pattern;
- um evento com `resourceType=S3Bucket` não corresponde ao pattern;
- o EventBridge aceitou a publicação sem entradas com falha;
- o destino iniciou exatamente uma execução correlacionada do workflow;
- a execução terminou em `SUCCEEDED` e retornou `status=skipped`;
- `TriageFinding` foi executado e `ContainTarget` não foi alcançado;
- a instância permaneceu `clean` e com o security group baseline;
- a DLQ permaneceu vazia.

O script preserva em um diretório temporário o evento publicado, as respostas de `PutEvents`, Step Functions e DLQ e os resultados locais de correspondência do pattern. Esses artefatos não devem ser versionados porque contêm identificadores específicos do ambiente.

### Observabilidade

O modo padrão executa somente consultas e verifica dashboard, alarmes, ações SNS, chave KMS, rotação, criptografia do tópico, autorização da Lambda de contenção e confirmação da assinatura de e-mail:

```powershell
.\scripts\Test-Observability.ps1
```

Resultado registrado:

```text
Passed: 21
Failed: 0
```

O teste de notificação exige autorização explícita:

```powershell
.\scripts\Test-Observability.ps1 `
  -ExecuteNotificationTest
```

Esse modo exige que o alarme selecionado esteja inicialmente em `OK`, altera-o temporariamente para `ALARM`, confirma no histórico a execução da ação SNS e restaura `OK` em um bloco `finally`. O teste manual validou a entrega completa e o e-mail foi recebido na assinatura configurada, sem gerar uma falha real de Lambda nem modificar o alvo EC2.

## Recuperação do alvo

O modo `-ExecuteContainment` do teste de orquestração tenta restaurar o alvo automaticamente, inclusive quando uma asserção posterior falha. Confirme sempre o estado exibido no resumo.

O teste independente `Test-Containment.ps1` deixa o alvo intencionalmente em quarentena. Depois dessa demonstração, restaure o estado baseline:

```powershell
$labInstanceId = (
    terraform -chdir=".\infra" output -raw lab_instance_id
).Trim()

$baselineSgId = (
    terraform -chdir=".\infra" output -raw baseline_security_group_id
).Trim()

aws ec2 modify-instance-attribute `
  --instance-id $labInstanceId `
  --groups $baselineSgId `
  --profile cloud-ir-lab `
  --region us-east-1

aws ec2 create-tags `
  --resources $labInstanceId `
  --tags "Key=IncidentStatus,Value=clean" `
  --profile cloud-ir-lab `
  --region us-east-1
```

Execute novamente as validações de fundação e triagem depois da recuperação.

## Verificação de drift

```powershell
terraform -chdir=".\infra" plan `
  -parallelism=1 `
  -detailed-exitcode

$driftExitCode = $LASTEXITCODE
Write-Host "Terraform drift exit code: $driftExitCode"
```

Interpretação:

| Exit code | Significado |
| ---: | --- |
| `0` | Plano concluído sem diferenças |
| `1` | Erro durante o planejamento |
| `2` | Plano concluído com mudanças |

## Post-mortem: autorização EC2

O primeiro teste real de contenção falhou com `UnauthorizedOperation` em `ec2:ModifyInstanceAttribute`.

A política autorizava somente o ARN da instância, mas a operação também foi avaliada para o security group de destino. O Terraform foi corrigido para permitir a ação exatamente sobre a instância do laboratório e o security group de quarentena, sem utilizar `Resource = "*"`.

O alvo permaneceu no estado baseline após a falha, e o incidente foi registrado como `failed` no DynamoDB. Após a correção IAM, o teste completo passou nas 54 verificações.

Esse caso demonstra por que testes unitários com mocks devem ser complementados por testes ponta a ponta em uma conta isolada: mocks validam o comportamento da aplicação, mas não reproduzem integralmente a avaliação de autorização da AWS.

## Post-mortem: leitura transitória do S3

Depois da primeira validação da orquestração, um refresh do Terraform informou incorretamente que o bucket de evidências havia sido removido e propôs seis criações e cinco substituições.

O plano não foi aplicado. A investigação confirmou que o bucket continuava existente e acessível por `HeadBucket`, pela API tradicional de tags e por `s3control list-tags-for-resource`. O state também preservava os seis recursos S3. Depois da limpeza do cache DNS, um novo plano retornou `No changes` com exit code `0`.

O evento reforça uma regra operacional do projeto: planos com recriação inesperada de recursos persistentes nunca devem ser aplicados antes da validação direta do recurso e do endpoint usado pelo provider.

## Post-mortem: falso negativo na validação do CloudWatch

A primeira execução automatizada do caminho elegível concluiu corretamente a Step Functions, a contenção, a persistência no DynamoDB, a notificação SNS e a recuperação do alvo, mas o teste informou que não havia encontrado o evento `containment_complete`.

Uma consulta direta ao log group encontrou exatamente um evento para o mesmo incidente. O registro foi ingerido poucos segundos após sua emissão, descartando atraso prolongado como causa. O problema foi isolado ao filtro literal passado à AWS CLI pelo Windows PowerShell: a automação falhava ao localizar um evento que já estava armazenado.

O validador foi corrigido para:

- consultar o intervalo de tempo sem `--filter-pattern` e correlacionar localmente o ID do incidente e o nome do evento;
- iniciar a janela cinco minutos antes da execução;
- repetir a consulta até 20 vezes, com intervalo de três segundos;
- preservar a resposta bruta em `cloudwatch-query.json`;
- salvar as evidências de Step Functions e DynamoDB antes da asserção do CloudWatch;
- executar a recuperação automática em `finally`.

Depois da correção, o caminho seguro passou em `23/23`, o caminho elegível passou em `40/40`, a fundação passou em `26/26` e o Terraform confirmou ausência de drift.

## Post-mortem: alarmes sem ação de notificação

A primeira versão da camada de observabilidade criou corretamente o dashboard e seis alarmes, mas a inspeção do estado real mostrou `0/6` alarmes com ação SNS. Os alarmes monitoravam as métricas, porém não notificariam a operação quando entrassem em `ALARM`.

A configuração foi corrigida com `alarm_actions` apontando para o tópico SNS de incidentes. Para suportar a publicação iniciada pelo CloudWatch em um tópico criptografado com uma política controlada pelo projeto, o tópico migrou de `alias/aws/sns` para uma chave KMS própria. A política permite `kms:Decrypt` e `kms:GenerateDataKey*` ao serviço CloudWatch, limitada à conta atual e ao padrão de ARN dos alarmes do laboratório.

A validação final confirmou:

- chave KMS `Enabled`, gerenciada pela conta e com rotação automática de 365 dias;
- tópico SNS usando a chave do projeto;
- autorização KMS da Lambda de contenção atualizada;
- seis de seis alarmes em `OK`, com ações habilitadas e direcionadas ao SNS;
- execução bem-sucedida da ação SNS no histórico do CloudWatch;
- restauração do alarme para `OK`;
- recebimento do e-mail de teste;
- Terraform sem drift.

## Custos e limpeza

O desenho evita NAT Gateway e mantém retenções curtas para reduzir custos. Mesmo assim, EC2, CloudWatch, SNS, SQS, DynamoDB, S3, Step Functions e demais serviços podem gerar cobrança. A chave KMS gerenciada pelo projeto possui cobrança recorrente enquanto existir, e dashboards e alarmes do CloudWatch também podem exceder a faixa gratuita conforme o uso.

Quando o laboratório não for mais necessário, gere e revise primeiro o plano de destruição:

```powershell
terraform -chdir=".\infra" plan `
  -destroy `
  -out="destroy.tfplan"
```

Somente depois de confirmar os recursos listados:

```powershell
terraform -chdir=".\infra" apply `
  ".\destroy.tfplan"
```

O bucket S3 precisa estar vazio para ser removido, salvo se a configuração definir explicitamente outro comportamento. Trate a destruição como uma operação irreversível.

## Documentação

- [Validação da fundação](docs/foundation-validation.md)
- [Validação da triagem](docs/triage-validation.md)
- [Validação da contenção e post-mortem](docs/containment-validation.md)
- [Validação da orquestração](docs/orchestration-validation.md)
- [Validação da ingestão por EventBridge](docs/eventbridge-validation.md)
- [Validação de observabilidade](docs/observability-validation.md)

## Limitações atuais

- o finding GuardDuty é sintético;
- a ingestão usa um barramento customizado e uma origem exclusiva do laboratório, não findings reais do GuardDuty no barramento default;
- ainda não existe aprovação humana;
- o modo elegível é explicitamente opt-in e limitado ao alvo descartável; a recuperação local é best-effort e ainda depende de credenciais e conectividade com a AWS;
- os alertas operacionais são entregues por e-mail; ainda não existe integração com ChatOps, on-call ou uma plataforma de gestão de incidentes;
- a evidência S3 contém finding normalizado, decisão e metadados da instância, mas ainda não inclui snapshot EBS, memória ou coleta dentro do sistema operacional;
- a retenção S3 segue o ciclo curto do laboratório e ainda não implementa Object Lock, legal hold ou cópia para uma conta forense separada;
- o alvo suporta somente o cenário controlado de uma instância com uma interface de rede;
- o laboratório não substitui um processo forense ou uma estratégia de contenção de produção.

## Próximas evoluções

- habilitar GuardDuty e integrar findings reais pelo barramento default em um ambiente dedicado;
- adicionar aprovação humana e recuperação controlada ao workflow;
- coletar snapshots EBS e outros artefatos forenses antes da contenção;
- adicionar Object Lock e replicação para uma conta forense em uma variante de produção;
- publicar métricas customizadas e indicadores de tempo de triagem, contenção e recuperação;
- integrar os alarmes a ChatOps ou a uma plataforma de gestão de incidentes;
- adicionar CI para testes Python, formatação e validação Terraform;
- adicionar controles DevSecOps, como análise estática e scan de credenciais.

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

## Referências

- [Amazon GuardDuty — EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Amazon EC2 — ModifyInstanceAttribute](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceAttribute.html)
- [AWS CLI — login para desenvolvimento local](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)
- [AWS SDKs and Tools — shared configuration profiles](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html)
- [AWS Step Functions — integração com Lambda](https://docs.aws.amazon.com/step-functions/latest/dg/connect-lambda.html)
- [AWS Step Functions — Choice state](https://docs.aws.amazon.com/step-functions/latest/dg/state-choice.html)
- [AWS Step Functions — tipos de workflow](https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html)
- [Amazon EventBridge — event buses](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus.html)
- [Amazon EventBridge — event patterns](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html)
- [Amazon EventBridge — retry e DLQ](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-retry-policy.html)
- [AWS CLI — test-event-pattern](https://docs.aws.amazon.com/cli/latest/reference/events/test-event-pattern.html)
- [AWS CLI — put-events](https://docs.aws.amazon.com/cli/latest/reference/events/put-events.html)
- [Amazon CloudWatch — dashboards](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Dashboards.html)
- [Amazon CloudWatch — ações de alarmes](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html)
- [Amazon CloudWatch — SetAlarmState](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_SetAlarmState.html)
- [Amazon CloudWatch Logs — FilterLogEvents API](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html)
- [Amazon SNS — criptografia em repouso](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html)
- [Amazon SNS — gerenciamento de chaves KMS](https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html)
- [AWS KMS — rotação de chaves](https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys-enable.html)
- [Amazon S3 — verificação de integridade de objetos](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html)
- [Amazon S3 — PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
- [Terraform plan command](https://developer.hashicorp.com/terraform/cli/commands/plan)
- [MITRE ATT&CK T1496.001 — Compute Hijacking](https://attack.mitre.org/techniques/T1496/001/)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
