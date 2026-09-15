# Validação de observabilidade

## Escopo

Esta validação cobre a camada de monitoramento operacional do AWS Cloud IR Automation Lab:

- dashboard do CloudWatch;
- alarme de falha de entrega do EventBridge;
- alarme da dead-letter queue do EventBridge;
- alarmes de falha e timeout do Step Functions;
- alarmes de erro das Lambdas de triagem e contenção;
- ações de notificação via SNS;
- criptografia do tópico de notificações com chave KMS gerenciada pelo projeto;
- entrega confirmada por e-mail;
- teste controlado de estado de alarme com recuperação automática.

O teste utiliza somente recursos sintéticos do laboratório. Ele não gera um erro real de Lambda, não altera o alvo EC2 e não inicia o workflow de resposta a incidentes.

## Sinais monitorados

| Componente | Métrica | Condição do alarme |
| --- | --- | --- |
| Regra do EventBridge | `AWS/Events FailedInvocations` | Pelo menos uma falha de invocação do destino em cinco minutos |
| DLQ do EventBridge | `AWS/SQS ApproximateNumberOfMessagesVisible` | Pelo menos uma mensagem visível em cinco minutos |
| Step Functions | `AWS/States ExecutionsFailed` | Pelo menos uma execução com falha em cinco minutos |
| Step Functions | `AWS/States ExecutionsTimedOut` | Pelo menos uma execução expirada em cinco minutos |
| Lambda de triagem | `AWS/Lambda Errors` | Pelo menos um erro em cinco minutos |
| Lambda de contenção | `AWS/Lambda Errors` | Pelo menos um erro em cinco minutos |

Todos os alarmes utilizam limiar igual a um, um período de avaliação, um datapoint para disparo e `notBreaching` para dados ausentes. A ação de ALARM publica no tópico SNS de incidentes.

## Dashboard

O dashboard `cloud-ir-lab-secops-overview` contém sete widgets:

- um widget de texto explicativo;
- cinco widgets de métricas;
- um widget de estado contendo os seis alarmes operacionais.

As visualizações cobrem execuções do workflow, entrega do EventBridge, invocações e erros de Lambda, duração p95 da resposta e backlog da DLQ do EventBridge.

## Criptografia das notificações

O tópico SNS de incidentes utiliza a chave KMS gerenciada pelo projeto exposta pelo alias:

```text
alias/cloud-ir-lab-incident-notifications
```

A chave é simétrica, está habilitada, é gerenciada pela conta e possui rotação automática a cada 365 dias. A política IAM da Lambda de contenção referencia essa chave para `kms:Decrypt` e `kms:GenerateDataKey*` durante a publicação de notificações criptografadas.

A política KMS permite que o serviço CloudWatch utilize a chave nas notificações dos alarmes, com restrições para a conta AWS atual e para o padrão de ARN dos alarmes do laboratório.

## Validação reproduzível

Execute primeiro a validação somente leitura:

```powershell
.\scripts\Test-Observability.ps1
```

O modo padrão verifica:

- disponibilidade da AWS CLI e do Terraform;
- identidade AWS;
- existência do dashboard e composição dos widgets;
- os seis alarmes e seus parâmetros operacionais;
- estado dos alarmes e ações SNS;
- cobertura das métricas;
- presença dos alarmes no dashboard;
- estado e rotação automática da chave KMS;
- criptografia do SNS com a chave do projeto;
- acesso IAM da contenção à chave;
- presença e confirmação da assinatura de e-mail.

## Teste controlado de notificação

O teste de notificação é opcional e exige um parâmetro explícito:

```powershell
.\scripts\Test-Observability.ps1 -ExecuteNotificationTest
```

O script exige que o alarme selecionado comece em `OK`, altera-o temporariamente para `ALARM`, aguarda o registro bem-sucedido da ação SNS e restaura o estado `OK` em um bloco `finally`.

Isso valida o seguinte caminho:

```text
CloudWatch alarm -> encrypted SNS topic -> confirmed email subscription
```

O operador deve confirmar o recebimento na caixa configurada. O histórico do CloudWatch confirma o sucesso da ação SNS, enquanto o recebimento na caixa de entrada confirma a entrega final do e-mail.

## Resultado validado

A validação manual foi concluída com sucesso:

- estado da chave KMS: `Enabled`;
- gerenciador da chave: `CUSTOMER`;
- rotação automática: habilitada, 365 dias;
- criptografia do SNS: chave do projeto confirmada;
- alarmes do CloudWatch: seis de seis em `OK`;
- ações dos alarmes: seis de seis direcionadas ao tópico SNS de incidentes;
- transição controlada no CloudWatch: bem-sucedida;
- histórico da ação SNS: bem-sucedido;
- recuperação do alarme: bem-sucedida;
- notificação por e-mail: recebida;
- verificação de drift do Terraform: exit code `0`.

Nenhum ID de conta, ARN de recurso, endereço de e-mail, ID de instância, ID de security group ou credencial é registrado neste documento.

## Notas operacionais

- O teste controlado é distinguido de uma falha real de Lambda porque o motivo do estado contém um identificador único `observability-test-*`.
- Não utilize o modo opcional quando o alarme selecionado já estiver em `ALARM` ou `INSUFFICIENT_DATA`.
- Se o teste falhar após a transição, verifique o estado do alarme e somente restaure `OK` após confirmar que não existe violação real da métrica.
- A chave KMS gerenciada pelo projeto possui cobrança recorrente enquanto existir.
- O Terraform permanece como fonte da verdade para as configurações de dashboard, alarmes, SNS, IAM e KMS.

## Referências

- [Amazon CloudWatch `SetAlarmState`](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_SetAlarmState.html)
- [Amazon CloudWatch `DescribeAlarmHistory`](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarmHistory.html)
- [Amazon SNS encryption key management](https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html)
- [AWS KMS key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys-enable.html)
