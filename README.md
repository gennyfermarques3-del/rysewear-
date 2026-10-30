# RYSE WEAR Backoffice

Sistema de vendas e estoque da RYSE WEAR.

- **No ar:** https://ryse-wear.vercel.app (Vercel, equipe "Gennyfer", projeto `ryse-wear`)
- **Banco de dados:** Supabase, projeto `ryse-wear` (`yhekjbxrsxvmqiloxxzx`)

## Pastas

| Pasta | O que é |
|---|---|
| `producao/` | Cópia exata do que está no ar (publicado em 23/10/2026). Use para voltar atrás se uma atualização der errado. |

## Atualizar a cópia

GitHub → **Actions** → **Backup do site (Vercel)** → **Run workflow**. O robô baixa de novo os arquivos do site e salva aqui.

## Cópia de segurança dos dados

Em 30/10/2026 foi feita uma cópia de todas as tabelas no próprio Supabase, no schema `backup_20261030`.
